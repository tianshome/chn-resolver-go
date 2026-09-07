// Package server implements the DNS front end: bounded UDP/TCP intake,
// request dispatch between the resolver and the forwarder, and response
// synthesis on the wire.
package server

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/config"
	"chn-resolver/internal/engine"
	"chn-resolver/internal/metrics"
	"chn-resolver/internal/resolve"
)

const (
	// maxUDPPayload caps outbound EDNS advertisement and inbound replies.
	maxUDPPayload = 1232
	// tcpAdmitTimeout bounds how long a TCP connection waits for a
	// concurrency slot before being dropped.
	tcpAdmitTimeout = 100 * time.Millisecond
	// drainGrace extends graceful shutdown past the per-query deadline.
	drainGrace = time.Second
)

// Server serves DNS on UDP and TCP with bounded concurrency.
type Server struct {
	svc *resolve.Service
	cfg *config.Config
	log *slog.Logger
	m   *metrics.Metrics

	sem chan struct{}
	wg  sync.WaitGroup

	upstreams []engine.Upstream

	udpConn *net.UDPConn
	tcpLn   net.Listener
}

// New creates a Server. upstreams are used for the forward path.
func New(svc *resolve.Service, cfg *config.Config, log *slog.Logger, m *metrics.Metrics, upstreams []engine.Upstream) *Server {
	return &Server{
		svc:       svc,
		cfg:       cfg,
		log:       log,
		m:         m,
		sem:       make(chan struct{}, cfg.MaxConcurrency),
		upstreams: upstreams,
	}
}

// ListenAndServe binds the configured listeners and serves until ctx is
// done, then drains in-flight queries for up to overall_timeout + 1s.
// If ready is non-nil, the actual bound address is sent on it once both
// listeners are up (used with port 0 for tests).
func (s *Server) ListenAndServe(ctx context.Context, ready chan<- string) error {
	addr := net.JoinHostPort(s.cfg.Bind, strconv.Itoa(s.cfg.Port))
	var bound net.Addr
	if s.cfg.UDP {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		s.udpConn = pc.(*net.UDPConn)
		bound = s.udpConn.LocalAddr()
		s.log.Info("listening", "transport", "udp", "addr", bound)
	}
	if s.cfg.TCP {
		// with port 0, share the UDP socket's ephemeral port so both
		// transports serve the same address
		tcpAddr := addr
		if bound != nil {
			tcpAddr = bound.String()
		}
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			if s.udpConn != nil {
				s.udpConn.Close()
			}
			return err
		}
		s.tcpLn = ln
		bound = s.tcpLn.Addr()
		s.log.Info("listening", "transport", "tcp", "addr", bound)
	}
	if ready != nil {
		ready <- bound.String()
	}

	// On shutdown, stop intake without killing in-flight queries: unblock
	// the UDP reader via a read deadline and close the TCP listener
	// (existing connections keep serving until their own deadlines).
	go func() {
		<-ctx.Done()
		if s.udpConn != nil {
			s.udpConn.SetReadDeadline(time.Now())
		}
		if s.tcpLn != nil {
			s.tcpLn.Close()
		}
	}()
	udpDone := make(chan struct{})
	tcpDone := make(chan struct{})
	if s.cfg.UDP {
		go func() {
			defer close(udpDone)
			s.serveUDP(ctx)
		}()
	}
	if s.cfg.TCP {
		go func() {
			defer close(tcpDone)
			s.serveTCP(ctx)
		}()
	}

	<-ctx.Done()
	// Wait for the intake loops to exit first: after that no further
	// wg.Add can happen and wg.Wait is safe to call.
	if s.cfg.UDP {
		<-udpDone
	}
	if s.cfg.TCP {
		<-tcpDone
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.log.Info("drained all in-flight queries")
	case <-time.After(s.cfg.OverallTimeout + drainGrace):
		s.log.Warn("drain timeout, exiting with in-flight queries")
	}
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	return nil
}

func (s *Server) serveUDP(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Warn("udp read", "err", err)
			continue
		}
		s.m.QueriesUDP.Add(1)
		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			s.m.ParseError.Add(1)
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			s.m.DroppedOverload.Add(1)
			s.log.Warn("overload: dropping udp query", "client", addr.String())
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.handleDatagram(req, addr)
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context) {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Warn("tcp accept", "err", err)
			continue
		}
		s.m.QueriesTCP.Add(1)
		select {
		case s.sem <- struct{}{}:
		case <-time.After(tcpAdmitTimeout):
			s.m.DroppedOverload.Add(1)
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.handleTCPConn(conn)
		}()
	}
}

func (s *Server) handleDatagram(req *dns.Msg, addr *net.UDPAddr) {
	// The query context is independent of the serve context: shutdown
	// stops intake but lets in-flight queries run to their own deadline.
	qctx, cancel := context.WithTimeout(context.Background(), s.cfg.OverallTimeout)
	defer cancel()
	s.m.Inflight.Add(1)
	defer s.m.Inflight.Add(-1)

	resp := s.handleRequest(qctx, req, addr.String())
	if resp == nil {
		return
	}
	truncateForUDP(req, resp, maxUDPPayload)
	wire, err := resp.Pack()
	if err != nil {
		s.log.Warn("pack udp response", "err", err)
		return
	}
	if _, err := s.udpConn.WriteToUDP(wire, addr); err != nil {
		s.log.Debug("udp write", "err", err)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()
	var lb [2]byte
	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.cfg.TCPIdleTimeout)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return // idle timeout, EOF, or reset
		}
		n := binary.BigEndian.Uint16(lb[:])
		data := make([]byte, n)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(data); err != nil {
			return // malformed frame: close the connection
		}
		// independent of the serve context: shutdown drains, not cancels
		qctx, cancel := context.WithTimeout(context.Background(), s.cfg.OverallTimeout)
		s.m.Inflight.Add(1)
		resp := s.handleRequest(qctx, req, peer)
		s.m.Inflight.Add(-1)
		cancel()
		if resp == nil {
			return
		}
		wire, err := resp.Pack()
		if err != nil {
			s.log.Warn("pack tcp response", "err", err)
			return
		}
		frame := make([]byte, 2+len(wire))
		binary.BigEndian.PutUint16(frame, uint16(len(wire)))
		copy(frame[2:], wire)
		if err := conn.SetWriteDeadline(time.Now().Add(s.cfg.OverallTimeout)); err != nil {
			return
		}
		if _, err := conn.Write(frame); err != nil {
			return
		}
	}
}

// truncateForUDP cuts a UDP reply to the client's advertised size (512
// without OPT), setting TC so the client retries over TCP.
func truncateForUDP(req, resp *dns.Msg, maxPayload uint16) {
	size := uint16(dns.MinMsgSize)
	if opt := req.IsEdns0(); opt != nil {
		if s := opt.UDPSize(); s >= dns.MinMsgSize && s <= maxPayload {
			size = s
		} else if s > maxPayload {
			size = maxPayload
		}
	}
	resp.Truncate(int(size))
}
