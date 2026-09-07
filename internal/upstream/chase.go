package upstream

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/policy"
)

// Chase resolves (qname, qtype) against one upstream, following CNAME
// chains breadth-first with a cycle guard and depth cap. Only the
// requested qtype is queried (unlike the Python implementation, which
// always chased A and AAAA together).
func Chase(ctx context.Context, cl *Client, addr netip.AddrPort, qname string, qtype uint16, maxHops int, attemptTimeout time.Duration, udpSize uint16) policy.Result {
	res := policy.Result{Server: addr.Addr()}
	name := normalize(qname)
	seen := map[string]bool{}
	pending := []string{name}
	lookups := 0

	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			res.State = policy.StateFailure
			res.ErrCategory = Category(err)
			return res
		}
		cur := pending[0]
		pending = pending[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		lookups++
		if lookups > maxHops {
			res.State = policy.StateFailure
			res.ErrCategory = "cname-maxdepth"
			return res
		}

		budget := hopBudget(ctx, attemptTimeout)
		if budget <= 0 {
			res.State = policy.StateFailure
			res.ErrCategory = "timeout"
			return res
		}

		q := new(dns.Msg)
		q.SetQuestion(cur, qtype)
		q.RecursionDesired = true
		q.SetEdns0(udpSize, false) // DO cleared: no DNSSEC records fetched

		resp, err := cl.Exchange(ctx, addr, q, budget)
		if err != nil {
			res.State = policy.StateFailure
			res.ErrCategory = Category(err)
			return res
		}

		switch resp.Rcode {
		case dns.RcodeSuccess:
		case dns.RcodeNameError:
			res.State = policy.StateNXDomain
			res.SOA = extractSOA(resp)
			return res
		default:
			res.State = policy.StateFailure
			res.ErrCategory = "rcode-" + dns.RcodeToString[resp.Rcode]
			return res
		}

		// A recursive upstream may return the whole chain in one message;
		// the terminal qtype rrset is all we need.
		var addrs []netip.Addr
		var minTTL uint32
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype != qtype {
				continue
			}
			ip, ok := rrAddr(rr)
			if !ok {
				continue
			}
			addrs = append(addrs, ip)
			if ttl := rr.Header().Ttl; minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
		if len(addrs) > 0 {
			res.State = policy.StateAnswer
			res.Addrs = dedupAddrs(addrs)
			res.MinTTL = minTTL
			return res
		}

		// Follow CNAMEs whose owner is the current name.
		var targets []string
		seenTarget := map[string]bool{}
		for _, rr := range resp.Answer {
			cn, ok := rr.(*dns.CNAME)
			if !ok || !strings.EqualFold(cn.Hdr.Name, cur) {
				continue
			}
			t := normalize(cn.Target)
			if t != "" && !seenTarget[t] {
				seenTarget[t] = true
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			res.State = policy.StateNoData
			res.SOA = extractSOA(resp)
			return res
		}
		for _, t := range targets {
			if !seen[t] {
				pending = append(pending, t)
			}
		}
	}
	// Queue exhausted without records.
	res.State = policy.StateNoData
	return res
}

func hopBudget(ctx context.Context, attempt time.Duration) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		if rem := time.Until(d); rem < attempt {
			attempt = rem
		}
	}
	if attempt < 0 {
		return 0
	}
	return attempt
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")) + "."
}

func rrAddr(rr dns.RR) (netip.Addr, bool) {
	switch v := rr.(type) {
	case *dns.A:
		ip, ok := netip.AddrFromSlice(v.A)
		return ip.Unmap(), ok
	case *dns.AAAA:
		ip, ok := netip.AddrFromSlice(v.AAAA)
		return ip, ok
	}
	return netip.Addr{}, false
}

func extractSOA(m *dns.Msg) *dns.SOA {
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

func dedupAddrs(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}
