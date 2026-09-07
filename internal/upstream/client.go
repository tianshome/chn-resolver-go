// Package upstream performs one-hop DNS exchanges against upstream
// resolvers and chases CNAME chains on their behalf.
package upstream

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Sentinel errors for categorizing exchange failures.
var (
	ErrTimeout  = errors.New("upstream timeout")
	ErrNetwork  = errors.New("upstream network error")
	ErrCanceled = errors.New("upstream canceled")
)

// Client performs one-hop exchanges: UDP first, TCP retry on truncation.
// Each exchange uses its own socket (fresh source port and ID space), which
// avoids ID-demux complexity; the kernel cost is negligible at this
// deployment's query rate. Shared and stateless across goroutines.
type Client struct {
	UDP *dns.Client
	TCP *dns.Client
}

func NewClient(udpSize uint16) *Client {
	udp := &dns.Client{Net: "udp", UDPSize: udpSize}
	tcp := &dns.Client{Net: "tcp", UDPSize: udpSize}
	return &Client{UDP: udp, TCP: tcp}
}

// Exchange sends q to addr within budget, retrying once over TCP if the
// UDP reply is truncated. ctx cancellation between attempts is honored.
func (c *Client) Exchange(ctx context.Context, addr netip.AddrPort, q *dns.Msg, budget time.Duration) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrCanceled
	}
	resp, err := c.exchangeNet(c.UDP, addr, q, budget)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		if err := ctx.Err(); err != nil {
			return nil, ErrCanceled
		}
		return c.exchangeNet(c.TCP, addr, q, budget)
	}
	return resp, nil
}

func (c *Client) exchangeNet(cl *dns.Client, addr netip.AddrPort, q *dns.Msg, budget time.Duration) (*dns.Msg, error) {
	cl.Timeout = budget
	resp, _, err := cl.Exchange(q.Copy(), addr.String())
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, ErrTimeout
		}
		return nil, ErrNetwork
	}
	return resp, nil
}

// Category maps exchange errors to policy result failure categories.
func Category(err error) string {
	switch {
	case errors.Is(err, ErrTimeout):
		return "timeout"
	case errors.Is(err, ErrCanceled):
		return "canceled"
	default:
		return "network"
	}
}
