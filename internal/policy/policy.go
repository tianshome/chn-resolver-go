// Package policy ports the multiresolver selection rules (_choose in
// resolver.py) as pure functions with no server or network dependencies.
package policy

import (
	"net/netip"

	"github.com/miekg/dns"
)

// State of a single upstream's resolution attempt.
type State uint8

const (
	// StateFailure covers timeouts, network errors, and SERVFAIL replies.
	StateFailure State = iota
	// StateNoData is NOERROR with an empty answer (name exists, type absent).
	StateNoData
	// StateNXDomain is NXDOMAIN.
	StateNXDomain
	// StateAnswer carries address records.
	StateAnswer
)

func (s State) String() string {
	switch s {
	case StateFailure:
		return "failure"
	case StateNoData:
		return "nodata"
	case StateNXDomain:
		return "nxdomain"
	case StateAnswer:
		return "answer"
	}
	return "unknown"
}

// Result is one upstream's outcome for a (qname, qtype) resolution.
type Result struct {
	Server      netip.Addr
	ServerChina bool
	Addrs       []netip.Addr // populated only when State == StateAnswer
	State       State
	SOA         *dns.SOA // populated for negative states
	MinTTL      uint32   // min rrset TTL among Addrs; only for StateAnswer
	ErrCategory string   // "timeout" | "network" | "servfail" | ...
}

// SelectResult is the policy decision.
type SelectResult struct {
	Policy string // one of the four Python policy names, verbatim
	Addrs  []netip.Addr
}

// Policy names, kept identical to the Python implementation.
const (
	PolicyOverride      = "override_non_china_from_non_china_resolvers"
	PolicyPreferChina   = "prefer_china_from_china_resolvers"
	PolicyAllNonChina   = "all_non_china_return_only_non_china_resolvers"
	PolicyFallbackChina = "fallback_china_addresses"
)

// Select is an exact port of _choose (resolver.py L189-224). Only results
// with StateAnswer contribute addresses; the qtype is implicit in Addrs
// (this resolver chases only the requested type, unlike Python's A+AAAA).
func Select(qname string, results []Result, isChina func(netip.Addr) bool, isOverride func(string) bool) SelectResult {
	var cnIPs, nonCNIPs, allIPs []netip.Addr
	for _, r := range results {
		if r.State != StateAnswer {
			continue
		}
		allIPs = append(allIPs, r.Addrs...)
		if r.ServerChina {
			cnIPs = append(cnIPs, r.Addrs...)
		} else {
			nonCNIPs = append(nonCNIPs, r.Addrs...)
		}
	}

	cnIPsChina := filter(cnIPs, isChina)
	nonCNIPsNonChina := filter(nonCNIPs, func(a netip.Addr) bool { return !isChina(a) })
	allChina := filter(allIPs, isChina)

	// Rule 1
	if len(cnIPsChina) > 0 && len(nonCNIPsNonChina) > 0 {
		if isOverride(qname) {
			return SelectResult{Policy: PolicyOverride, Addrs: dedup(nonCNIPsNonChina)}
		}
		return SelectResult{Policy: PolicyPreferChina, Addrs: dedup(cnIPsChina)}
	}

	// Rule 2: no China IP returned by anyone
	if len(allChina) == 0 {
		if len(nonCNIPs) > 0 {
			return SelectResult{Policy: PolicyAllNonChina, Addrs: dedup(nonCNIPs)}
		}
		return SelectResult{Policy: PolicyAllNonChina, Addrs: dedup(allIPs)}
	}

	// Rule 3: prefer China-resolver China IPs, else any China IPs
	if len(cnIPsChina) > 0 {
		return SelectResult{Policy: PolicyFallbackChina, Addrs: dedup(cnIPsChina)}
	}
	return SelectResult{Policy: PolicyFallbackChina, Addrs: dedup(allChina)}
}

// FinalizeNegative decides the rcode when no upstream returned records.
// ok=false means SERVFAIL. NXDOMAIN/NODATA are only reported when every
// non-failed upstream agrees — disagreement is treated as a poisoning
// signal and never negative-cached.
func FinalizeNegative(results []Result) (rcode int, soa *dns.SOA, ok bool) {
	var nx, nodata []Result
	for _, r := range results {
		switch r.State {
		case StateNXDomain:
			nx = append(nx, r)
		case StateNoData:
			nodata = append(nodata, r)
		}
	}
	switch {
	case len(nx) > 0 && len(nodata) == 0:
		return dns.RcodeNameError, firstSOA(nx), true
	case len(nx) == 0 && len(nodata) > 0:
		return dns.RcodeSuccess, firstSOA(nodata), true
	default:
		return dns.RcodeServerFailure, nil, false
	}
}

// SelectTTL returns the minimum MinTTL across the results that contributed
// the chosen addresses (first-owner wins, matching dedup order).
func SelectTTL(addrs []netip.Addr, results []Result) (uint32, bool) {
	owner := make(map[netip.Addr]uint32)
	for _, r := range results {
		if r.State != StateAnswer {
			continue
		}
		for _, a := range r.Addrs {
			if _, ok := owner[a]; !ok {
				owner[a] = r.MinTTL
			}
		}
	}
	var ttl uint32
	found := false
	for _, a := range addrs {
		t, ok := owner[a]
		if !ok {
			continue
		}
		if !found || t < ttl {
			ttl = t
			found = true
		}
	}
	return ttl, found
}

func firstSOA(rs []Result) *dns.SOA {
	for _, r := range rs {
		if r.SOA != nil {
			return r.SOA
		}
	}
	return nil
}

func filter(addrs []netip.Addr, keep func(netip.Addr) bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

func dedup(addrs []netip.Addr) []netip.Addr {
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
