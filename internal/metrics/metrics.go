// Package metrics holds process counters and renders them as Prometheus
// text format on demand.
package metrics

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"chn-resolver/internal/policy"
)

type UpstreamMetrics struct {
	Addr string
	// results by policy.State.String()
	Results map[string]*atomic.Uint64
	// failures by category (timeout, network, servfail...)
	Failures map[string]*atomic.Uint64
}

type Metrics struct {
	start time.Time

	QueriesUDP, QueriesTCP          atomic.Uint64
	Resolved, Forwarded             atomic.Uint64
	FormErr, DroppedOverload        atomic.Uint64
	ParseError                      atomic.Uint64
	AnswersNOERROR, AnswersNXDomain atomic.Uint64
	AnswersNODATA, AnswersSERVFAIL  atomic.Uint64
	Policies                        map[string]*atomic.Uint64
	Inflight                        atomic.Int64
	Upstreams                       []*UpstreamMetrics
}

// New creates metrics with per-upstream counters pre-registered.
func New(upstreamAddrs []string) *Metrics {
	m := &Metrics{
		start:    time.Now(),
		Policies: make(map[string]*atomic.Uint64),
	}
	for _, p := range []string{
		policy.PolicyOverride, policy.PolicyPreferChina,
		policy.PolicyAllNonChina, policy.PolicyFallbackChina,
	} {
		m.Policies[p] = &atomic.Uint64{}
	}
	for _, a := range upstreamAddrs {
		m.Upstreams = append(m.Upstreams, &UpstreamMetrics{
			Addr:     a,
			Results:  make(map[string]*atomic.Uint64),
			Failures: make(map[string]*atomic.Uint64),
		})
	}
	return m
}

// RecordUpstreamResult bumps the per-upstream counter for a result state.
func (m *Metrics) RecordUpstreamResult(idx int, state string) {
	if idx < 0 || idx >= len(m.Upstreams) {
		return
	}
	m.counter(m.Upstreams[idx].Results, state).Add(1)
}

// RecordUpstreamFailure bumps the per-upstream failure counter.
func (m *Metrics) RecordUpstreamFailure(idx int, category string) {
	if idx < 0 || idx >= len(m.Upstreams) {
		return
	}
	m.counter(m.Upstreams[idx].Failures, category).Add(1)
}

// RecordPolicy bumps the policy counter.
func (m *Metrics) RecordPolicy(name string) {
	if c, ok := m.Policies[name]; ok {
		c.Add(1)
	}
}

var mu sync.Mutex

// counter is a lazily created named counter (callers may pass dynamic
// state/category names).
func (m *Metrics) counter(dst map[string]*atomic.Uint64, name string) *atomic.Uint64 {
	if c, ok := dst[name]; ok {
		return c
	}
	mu.Lock()
	defer mu.Unlock()
	if c, ok := dst[name]; ok {
		return c
	}
	c := &atomic.Uint64{}
	dst[name] = c
	return c
}

// Write renders Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	fmt.Fprintf(w, "# TYPE chn_resolver_queries_total counter\n")
	fmt.Fprintf(w, "chn_resolver_queries_total{transport=\"udp\"} %d\n", m.QueriesUDP.Load())
	fmt.Fprintf(w, "chn_resolver_queries_total{transport=\"tcp\"} %d\n", m.QueriesTCP.Load())
	fmt.Fprintf(w, "# TYPE chn_resolver_outcomes_total counter\n")
	fmt.Fprintf(w, "chn_resolver_outcomes_total{outcome=\"resolved\"} %d\n", m.Resolved.Load())
	fmt.Fprintf(w, "chn_resolver_outcomes_total{outcome=\"forwarded\"} %d\n", m.Forwarded.Load())
	fmt.Fprintf(w, "chn_resolver_outcomes_total{outcome=\"formerr\"} %d\n", m.FormErr.Load())
	fmt.Fprintf(w, "chn_resolver_outcomes_total{outcome=\"dropped_overload\"} %d\n", m.DroppedOverload.Load())
	fmt.Fprintf(w, "chn_resolver_outcomes_total{outcome=\"parse_error\"} %d\n", m.ParseError.Load())
	fmt.Fprintf(w, "# TYPE chn_resolver_answers_total counter\n")
	fmt.Fprintf(w, "chn_resolver_answers_total{rcode=\"noerror\"} %d\n", m.AnswersNOERROR.Load())
	fmt.Fprintf(w, "chn_resolver_answers_total{rcode=\"nxdomain\"} %d\n", m.AnswersNXDomain.Load())
	fmt.Fprintf(w, "chn_resolver_answers_total{rcode=\"nodata\"} %d\n", m.AnswersNODATA.Load())
	fmt.Fprintf(w, "chn_resolver_answers_total{rcode=\"servfail\"} %d\n", m.AnswersSERVFAIL.Load())
	fmt.Fprintf(w, "# TYPE chn_resolver_policy_total counter\n")
	for _, p := range []string{
		policy.PolicyOverride, policy.PolicyPreferChina,
		policy.PolicyAllNonChina, policy.PolicyFallbackChina,
	} {
		fmt.Fprintf(w, "chn_resolver_policy_total{policy=%q} %d\n", p, m.Policies[p].Load())
	}
	fmt.Fprintf(w, "# TYPE chn_resolver_upstream_results_total counter\n")
	for _, u := range m.Upstreams {
		for state, c := range u.Results {
			fmt.Fprintf(w, "chn_resolver_upstream_results_total{upstream=%q,state=%q} %d\n", u.Addr, state, c.Load())
		}
		for category, c := range u.Failures {
			fmt.Fprintf(w, "chn_resolver_upstream_failures_total{upstream=%q,category=%q} %d\n", u.Addr, category, c.Load())
		}
	}
	fmt.Fprintf(w, "# TYPE chn_resolver_inflight gauge\n")
	fmt.Fprintf(w, "chn_resolver_inflight %d\n", m.Inflight.Load())
	fmt.Fprintf(w, "# TYPE chn_resolver_uptime_seconds gauge\n")
	fmt.Fprintf(w, "chn_resolver_uptime_seconds %.0f\n", time.Since(m.start).Seconds())
}
