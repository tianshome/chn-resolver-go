package server

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"

	"chn-resolver/internal/cache"
)

// handleRequest classifies the request and dispatches to the resolver or
// the forwarder. It returns a response for the client's ID, or nil to
// close/drop (never for well-formed requests).
func (s *Server) handleRequest(ctx context.Context, req *dns.Msg, peer string) *dns.Msg {
	if len(req.Question) == 0 {
		s.m.FormErr.Add(1)
		return rcodeReply(req, dns.RcodeFormatError)
	}

	q := req.Question[0]

	if opt := req.IsEdns0(); opt != nil && opt.Version() != 0 {
		resp := rcodeReply(req, dns.RcodeBadVers)
		resp.SetEdns0(maxUDPPayload, false)
		return resp
	}

	if len(req.Question) != 1 || q.Qclass != dns.ClassINET ||
		req.Opcode != dns.OpcodeQuery ||
		(q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
		s.m.Forwarded.Add(1)
		return s.forward(ctx, req)
	}

	v, err := s.svc.Lookup(ctx, q.Name, q.Qtype)
	if err != nil {
		// deadline exceeded or canceled (e.g. singleflight waiter)
		s.m.AnswersSERVFAIL.Add(1)
		s.log.Debug("lookup failed", "qname", q.Name, "qtype", q.Qtype, "err", err, "peer", peer)
		return rcodeReply(req, dns.RcodeServerFailure)
	}
	s.m.Resolved.Add(1)

	resp := s.synthesize(req, q, v)
	s.log.Debug("resolved",
		"qname", q.Name, "qtype", q.Qtype, "policy", v.Policy,
		"rcode", dns.RcodeToString[resp.Rcode], "addrs", len(v.Addrs),
		"peer", peer)
	return resp
}

func (s *Server) synthesize(req *dns.Msg, q dns.Question, v cache.Value) *dns.Msg {
	var resp *dns.Msg
	switch {
	case len(v.Addrs) > 0:
		s.m.RecordPolicy(v.Policy)
		s.m.AnswersNOERROR.Add(1)
		resp = buildPositive(req, q, v.Addrs, v.TTL)
	case v.RCode == dns.RcodeNameError:
		s.m.AnswersNXDomain.Add(1)
		resp = buildNegative(req, dns.RcodeNameError, v.SOA, v.TTL)
	case v.RCode == dns.RcodeSuccess:
		s.m.AnswersNODATA.Add(1)
		resp = buildNegative(req, dns.RcodeSuccess, v.SOA, v.TTL)
	default:
		s.m.AnswersSERVFAIL.Add(1)
		resp = rcodeReply(req, dns.RcodeServerFailure)
	}
	applyEDNS(req, resp)
	return resp
}

// buildPositive synthesizes a single-rrset NOERROR answer for the original
// qname with the policy-chosen addresses.
func buildPositive(req *dns.Msg, q dns.Question, addrs []netip.Addr, ttl uint32) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Compress = true
	for _, a := range addrs {
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: ttl}
		var rr dns.RR
		if q.Qtype == dns.TypeA {
			rr = &dns.A{Hdr: hdr, A: a.AsSlice()}
		} else {
			rr = &dns.AAAA{Hdr: hdr, AAAA: a.AsSlice()}
		}
		resp.Answer = append(resp.Answer, rr)
	}
	return resp
}

// buildNegative synthesizes NXDOMAIN or NODATA with the upstream SOA in
// authority, at the negative-cache TTL.
func buildNegative(req *dns.Msg, rcode int, soa *dns.SOA, ttl uint32) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Rcode = rcode
	if soa != nil {
		c := dns.Copy(soa).(*dns.SOA)
		c.Hdr.Ttl = ttl
		resp.Ns = append(resp.Ns, c)
	}
	return resp
}

func rcodeReply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode
	return resp
}

// applyEDNS adds an OPT echoing the client's advertised size (capped),
// with DO cleared: this server is not a DNSSEC endpoint.
func applyEDNS(req, resp *dns.Msg) {
	if req.IsEdns0() == nil || resp.IsEdns0() != nil {
		return
	}
	size := int(req.IsEdns0().UDPSize())
	if size > maxUDPPayload {
		size = maxUDPPayload
	}
	if size < dns.MinMsgSize {
		size = dns.MinMsgSize
	}
	resp.SetEdns0(uint16(size), false)
}
