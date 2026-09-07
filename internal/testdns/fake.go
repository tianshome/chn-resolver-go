// Package testdns provides a fake DNS upstream for tests: a programmable
// zone map with per-name delays, truncation, and drop behavior, served on
// ephemeral UDP and TCP ports on 127.0.0.1.
package testdns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Zone is a canned zone served by Server. A name with records but no
// matching qtype answers NODATA (+SOA); an unknown name answers NXDOMAIN
// (+SOA). Records are returned as stored — no CNAME chasing, so clients
// exercise their own chase logic.
type Zone struct {
	// Records: name (FQDN, any case) -> qtype -> RRs
	Records map[string]map[uint16][]dns.RR
	// Delay sleeps before answering; DelayNames overrides per name.
	Delay      time.Duration
	DelayNames map[string]time.Duration
	// TruncateUDP sets TC on UDP answers (client must retry TCP).
	TruncateUDP bool
	// DropUDP never answers on UDP (simulates a black-holed upstream).
	DropUDP bool

	hits atomic.Int64
	mu   sync.Mutex
}

func (z *Zone) Hits() int64 { return z.hits.Load() }

func (z *Zone) delayFor(name string) time.Duration {
	if d, ok := z.DelayNames[strings.ToLower(name)]; ok {
		return d
	}
	return z.Delay
}

func (z *Zone) soa(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:     "ns1.example.",
		Mbox:   "hostmaster.example.",
		Serial: 1, Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 300,
	}
}

func (z *Zone) Handler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		z.hits.Add(1)
		if len(r.Question) != 1 {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		if d := z.delayFor(name); d > 0 {
			time.Sleep(d)
		}
		_, isUDP := w.RemoteAddr().(*net.UDPAddr)
		if isUDP && z.DropUDP {
			return // never reply
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if isUDP && z.TruncateUDP {
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		z.mu.Lock()
		byType := z.Records[name]
		z.mu.Unlock()
		if byType == nil {
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, z.soa(name))
			_ = w.WriteMsg(m)
			return
		}
		if rrs := byType[q.Qtype]; rrs != nil {
			m.Answer = append(m.Answer, rrs...)
			_ = w.WriteMsg(m)
			return
		}
		// NODATA
		m.Ns = append(m.Ns, z.soa(name))
		_ = w.WriteMsg(m)
	}
}

// Server runs a handler on ephemeral 127.0.0.1 UDP+TCP ports.
type Server struct {
	UDPAddr net.Addr
	TCPAddr net.Addr
	udp     *dns.Server
	tcp     *dns.Server
}

// StartZone serves a Zone.
func StartZone(t *testing.T, z *Zone) *Server {
	t.Helper()
	return Start(t, z.Handler())
}

// Start serves a custom handler. UDP and TCP share one port so clients can
// retry the same address over TCP after truncation, as with real upstreams.
func Start(t *testing.T, h dns.HandlerFunc) *Server {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	s := &Server{
		UDPAddr: pc.LocalAddr(),
		TCPAddr: ln.Addr(),
		udp:     &dns.Server{PacketConn: pc, Handler: h},
		tcp:     &dns.Server{Listener: ln, Handler: h},
	}
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	t.Cleanup(func() { s.Close() })
	return s
}

func (s *Server) Close() {
	_ = s.udp.Shutdown()
	_ = s.tcp.Shutdown()
}

func PortOf(a net.Addr) int {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.Port
	case *net.TCPAddr:
		return v.Port
	}
	return 0
}
