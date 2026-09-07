package server

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/upstream"
)

// forward relays non-A/AAAA traffic to the configured upstreams in order,
// with per-attempt timeout and UDP→TCP fallback on truncation. The first
// success is relayed verbatim with the client's ID restored; if every
// upstream fails, the client gets SERVFAIL.
func (s *Server) forward(ctx context.Context, req *dns.Msg) *dns.Msg {
	for i, u := range s.upstreams {
		if ctx.Err() != nil {
			break
		}
		budget := s.cfg.ForwardTimeout
		if d, ok := ctx.Deadline(); ok {
			if rem := time.Until(d); rem < budget {
				budget = rem
			}
		}
		if budget <= 0 {
			break
		}
		q := req.Copy()
		q.Id = dns.Id()
		resp, err := u.Client.Exchange(ctx, u.Addr, q, budget)
		if err != nil {
			s.m.RecordUpstreamFailure(i, upstream.Category(err))
			continue
		}
		s.m.RecordUpstreamResult(i, "forwarded")
		resp.Id = req.Id
		return resp
	}
	s.m.AnswersSERVFAIL.Add(1)
	return rcodeReply(req, dns.RcodeServerFailure)
}
