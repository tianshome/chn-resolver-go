// Package engine fans queries out to all upstreams concurrently, applies
// the selection policy as soon as it can, and bounds stuck upstreams by
// per-attempt timeouts instead of one flat overall timeout.
package engine

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/china"
	"chn-resolver/internal/overrides"
	"chn-resolver/internal/policy"
	"chn-resolver/internal/upstream"
)

// Assets are the static, reloadable inputs to classification and policy.
type Assets struct {
	China     *china.Index
	Overrides *overrides.Set
}

// Upstream is one configured resolver with its transport client.
type Upstream struct {
	Addr    netip.AddrPort
	InChina bool // precomputed: role override or prefix classification
	Client  *upstream.Client
}

// Engine fans out to Upstreams and finalizes results.
type Engine struct {
	upstreams      []Upstream
	attemptTimeout time.Duration
	maxHops        int
	udpSize        uint16
	assets         atomic.Pointer[Assets]
	// OnResult, if set, is called for each upstream outcome as it arrives
	// (used for metrics; results of early-returned stragglers are not
	// reported).
	OnResult func(idx int, state policy.State, category string)
}

// Result of one full resolution.
type Result struct {
	Policy string
	Addrs  []netip.Addr
	RCode  int
	SOA    *dns.SOA
	TTL    uint32
	// Complete is false when the engine answered before every upstream
	// finished; such results must not be cached.
	Complete bool
	Reports  []Report
}

// Report is per-upstream debug information.
type Report struct {
	Server      netip.Addr
	State       policy.State
	Latency     time.Duration
	ErrCategory string
}

func New(assets *Assets, upstreams []Upstream, attemptTimeout time.Duration, maxHops int, udpSize uint16) *Engine {
	e := &Engine{
		upstreams:      upstreams,
		attemptTimeout: attemptTimeout,
		maxHops:        maxHops,
		udpSize:        udpSize,
	}
	e.assets.Store(assets)
	return e
}

// UpdateAssets swaps in a freshly loaded asset bundle (SIGHUP reload).
func (e *Engine) UpdateAssets(a *Assets) { e.assets.Store(a) }

// Resolve fans out and finalizes. It returns as soon as the policy branch
// is stable (rule 1), or when all upstreams have finished or failed, or at
// the overall deadline — whichever comes first. A partial success is never
// turned into SERVFAIL by a slow upstream.
func (e *Engine) Resolve(ctx context.Context, qname string, qtype uint16) Result {
	assets := e.assets.Load()
	fanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	n := len(e.upstreams)
	ch := make(chan outcome, n)
	for i, u := range e.upstreams {
		i, u := i, u
		go func() {
			start := time.Now()
			r := upstream.Chase(fanCtx, u.Client, u.Addr, qname, qtype, e.maxHops, e.attemptTimeout, e.udpSize)
			r.Server = u.Addr.Addr()
			r.ServerChina = u.InChina
			ch <- outcome{r, time.Since(start), i}
		}()
	}

	results := make([]policy.Result, 0, n)
	reports := make([]Report, 0, n)
	for received := 0; received < n; received++ {
		select {
		case o := <-ch:
			if e.OnResult != nil {
				e.OnResult(o.idx, o.result.State, o.result.ErrCategory)
			}
			results = append(results, o.result)
			reports = append(reports, Report{Server: o.result.Server, State: o.result.State, Latency: o.latency, ErrCategory: o.result.ErrCategory})
			if len(results) == n {
				return e.finalize(assets, qname, results, reports, true)
			}
			if earlyStable(assets, qname, results) {
				return e.finalize(assets, qname, results, reports, false)
			}
		case <-ctx.Done():
			return e.finalize(assets, qname, results, reports, false)
		}
	}
	return e.finalize(assets, qname, results, reports, true)
}

type outcome struct {
	result  policy.Result
	latency time.Duration
	idx     int
}

// earlyStable reports whether rule 1's branch is decided: a China-class
// resolver returned a China IP and a non-China-class resolver returned a
// non-China IP. Both conditions are monotonic — later completions can
// extend the chosen set but can never change the branch.
func earlyStable(assets *Assets, qname string, results []policy.Result) bool {
	var cnChina, ncNonChina bool
	for _, r := range results {
		if r.State != policy.StateAnswer {
			continue
		}
		for _, a := range r.Addrs {
			isCN := assets.China.Contains(a)
			if r.ServerChina && isCN {
				cnChina = true
			}
			if !r.ServerChina && !isCN {
				ncNonChina = true
			}
		}
	}
	return cnChina && ncNonChina
}

func (e *Engine) finalize(assets *Assets, qname string, results []policy.Result, reports []Report, complete bool) Result {
	out := Result{Complete: complete, Reports: reports}
	hasAnswer := false
	for _, r := range results {
		if r.State == policy.StateAnswer {
			hasAnswer = true
			break
		}
	}
	if hasAnswer {
		sel := policy.Select(qname, results, assets.China.Contains, assets.Overrides.Match)
		out.Policy = sel.Policy
		out.Addrs = sel.Addrs
		out.RCode = dns.RcodeSuccess
		out.TTL, _ = policy.SelectTTL(sel.Addrs, results)
		return out
	}
	rcode, soa, ok := policy.FinalizeNegative(results)
	if ok {
		out.RCode, out.SOA = rcode, soa
	} else {
		out.RCode = dns.RcodeServerFailure
	}
	return out
}
