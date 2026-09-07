package policy

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// chinaSet mirrors the Python test fixtures: 1.1.1.0/24 and 2001:db8::/32
// are the "China" prefixes.
func chinaSet() map[netip.Addr]bool {
	return map[netip.Addr]bool{
		mustAddr("1.1.1.9"):     true,
		mustAddr("1.1.1.1"):     true,
		mustAddr("1.1.1.2"):     true,
		mustAddr("2001:db8::9"): true,
	}
}

func isChina(set map[netip.Addr]bool) func(netip.Addr) bool {
	return func(a netip.Addr) bool { return set[a] }
}

func noOverride(string) bool { return false }

func answer(server string, china bool, addrs ...string) Result {
	r := Result{Server: mustAddr(server), ServerChina: china, State: StateAnswer}
	for _, a := range addrs {
		r.Addrs = append(r.Addrs, mustAddr(a))
	}
	r.MinTTL = 300
	return r
}

func failure(server string, china bool) Result {
	return Result{Server: mustAddr(server), ServerChina: china, State: StateFailure, ErrCategory: "timeout"}
}

func soaResult(server string, china bool, state State, soa *dns.SOA) Result {
	return Result{Server: mustAddr(server), ServerChina: china, State: state, SOA: soa}
}

func testSOA(ttl, minttl uint32) *dns.SOA {
	return &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}, Minttl: minttl}
}

// Port of test_override_prefers_non_china_when_condition_met (A-type part).
func TestOverridePrefersNonChinaA(t *testing.T) {
	results := []Result{
		answer("1.1.1.1", true, "1.1.1.9"),
		answer("8.8.8.8", false, "9.9.9.9", "2001:4860:4860::8888"),
	}
	sel := Select("example.com", results, isChina(chinaSet()), func(q string) bool { return q == "example.com" })
	if sel.Policy != PolicyOverride {
		t.Errorf("policy = %q, want %q", sel.Policy, PolicyOverride)
	}
	want := []netip.Addr{mustAddr("9.9.9.9"), mustAddr("2001:4860:4860::8888")}
	assertAddrs(t, sel.Addrs, want)
}

// Override branch exercised with a China AAAA from the China resolver.
func TestOverridePrefersNonChinaAAAA(t *testing.T) {
	results := []Result{
		answer("1.1.1.1", true, "2001:db8::9"),
		answer("8.8.8.8", false, "2001:4860:4860::8888"),
	}
	sel := Select("example.com", results, isChina(chinaSet()), func(q string) bool { return true })
	if sel.Policy != PolicyOverride || len(sel.Addrs) != 1 || sel.Addrs[0] != mustAddr("2001:4860:4860::8888") {
		t.Errorf("override AAAA: %+v", sel)
	}
}

func TestPreferChinaFromChinaResolvers(t *testing.T) {
	results := []Result{
		answer("1.1.1.1", true, "1.1.1.9"),
		answer("8.8.8.8", false, "9.9.9.9"),
	}
	sel := Select("example.com", results, isChina(chinaSet()), noOverride)
	if sel.Policy != PolicyPreferChina || len(sel.Addrs) != 1 || sel.Addrs[0] != mustAddr("1.1.1.9") {
		t.Errorf("prefer china: %+v", sel)
	}
}

// Port of test_all_non_china_returns_only_non_china_resolvers.
func TestAllNonChinaReturnsOnlyNonChinaResolvers(t *testing.T) {
	results := []Result{
		answer("1.1.1.1", true, "9.9.9.9"),
		answer("8.8.8.8", false, "8.8.4.4", "2001:4860:4860::8888"),
	}
	sel := Select("foo.example", results, isChina(chinaSet()), noOverride)
	if sel.Policy != PolicyAllNonChina {
		t.Errorf("policy = %q, want %q", sel.Policy, PolicyAllNonChina)
	}
	// 9.9.9.9 came from the China resolver and must be excluded.
	want := []netip.Addr{mustAddr("8.8.4.4"), mustAddr("2001:4860:4860::8888")}
	assertAddrs(t, sel.Addrs, want)
}

// Rule 3: China IP exists but only from a non-China resolver.
func TestFallbackChinaFromAnyResolver(t *testing.T) {
	results := []Result{
		answer("1.1.1.1", true, "9.9.9.9"),
		answer("8.8.8.8", false, "1.1.1.9"),
	}
	sel := Select("foo.example", results, isChina(chinaSet()), noOverride)
	if sel.Policy != PolicyFallbackChina || len(sel.Addrs) != 1 || sel.Addrs[0] != mustAddr("1.1.1.9") {
		t.Errorf("fallback: %+v", sel)
	}
}

// Rule 3 with a stuck foreign upstream: the China side alone still answers.
func TestChinaOnlyAnswersWhenForeignStuck(t *testing.T) {
	results := []Result{
		answer("1.1.1.1", true, "1.1.1.9"),
		failure("8.8.8.8", false),
	}
	sel := Select("foo.example", results, isChina(chinaSet()), noOverride)
	if sel.Policy != PolicyFallbackChina || len(sel.Addrs) != 1 || sel.Addrs[0] != mustAddr("1.1.1.9") {
		t.Errorf("china-only: %+v", sel)
	}
}

// Rule 2 with a stuck China upstream: the foreign side alone answers.
func TestForeignOnlyAnswersWhenChinaStuck(t *testing.T) {
	results := []Result{
		failure("1.1.1.1", true),
		answer("8.8.8.8", false, "9.9.9.9"),
	}
	sel := Select("foo.example", results, isChina(chinaSet()), noOverride)
	if sel.Policy != PolicyAllNonChina || len(sel.Addrs) != 1 || sel.Addrs[0] != mustAddr("9.9.9.9") {
		t.Errorf("foreign-only: %+v", sel)
	}
}

func TestDedupKeepsOrder(t *testing.T) {
	results := []Result{
		answer("1.1.1.1", true, "1.1.1.9", "1.1.1.1"),
		answer("2.2.2.2", true, "1.1.1.9", "1.1.1.2"),
		answer("8.8.8.8", false, "9.9.9.9"),
	}
	sel := Select("foo.example", results, isChina(chinaSet()), noOverride)
	want := []netip.Addr{mustAddr("1.1.1.9"), mustAddr("1.1.1.1"), mustAddr("1.1.1.2")}
	assertAddrs(t, sel.Addrs, want)
}

// Invariant: if any result carried records, Select returns a non-empty set.
func TestRecordsExistImpliesNonEmpty(t *testing.T) {
	cases := [][]Result{
		{answer("1.1.1.1", true, "9.9.9.9"), failure("8.8.8.8", false)},
		{answer("8.8.8.8", false, "1.1.1.9"), failure("1.1.1.1", true)},
		{answer("1.1.1.1", true, "9.9.9.9"), answer("8.8.8.8", false, "9.9.9.9")},
		{failure("1.1.1.1", true), answer("8.8.8.8", false, "8.8.4.4")},
	}
	for i, results := range cases {
		sel := Select("foo.example", results, isChina(chinaSet()), noOverride)
		if len(sel.Addrs) == 0 {
			t.Errorf("case %d: records existed but Select returned empty (policy %q)", i, sel.Policy)
		}
	}
}

func TestFinalizeNegativeMatrix(t *testing.T) {
	soa := testSOA(3600, 300)
	cases := []struct {
		name    string
		results []Result
		rcode   int
		ok      bool
	}{
		{"all nxdomain", []Result{
			soaResult("1.1.1.1", true, StateNXDomain, soa),
			soaResult("8.8.8.8", false, StateNXDomain, soa),
		}, dns.RcodeNameError, true},
		{"all nodata", []Result{
			soaResult("1.1.1.1", true, StateNoData, soa),
			soaResult("8.8.8.8", false, StateNoData, soa),
		}, dns.RcodeSuccess, true},
		{"mixed nxdomain nodata", []Result{
			soaResult("1.1.1.1", true, StateNXDomain, soa),
			soaResult("8.8.8.8", false, StateNoData, soa),
		}, dns.RcodeServerFailure, false},
		{"failures only", []Result{
			failure("1.1.1.1", true),
			failure("8.8.8.8", false),
		}, dns.RcodeServerFailure, false},
		{"failure plus nxdomain", []Result{
			failure("1.1.1.1", true),
			soaResult("8.8.8.8", false, StateNXDomain, soa),
		}, dns.RcodeNameError, true},
		{"empty", nil, dns.RcodeServerFailure, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rcode, gotSOA, ok := FinalizeNegative(c.results)
			if rcode != c.rcode || ok != c.ok {
				t.Errorf("FinalizeNegative = (%d, %v), want (%d, %v)", rcode, ok, c.rcode, c.ok)
			}
			if ok && gotSOA == nil {
				t.Errorf("expected SOA for ok negative result")
			}
		})
	}
}

func TestSelectTTL(t *testing.T) {
	r1 := answer("1.1.1.1", true, "1.1.1.9")
	r1.MinTTL = 60
	r2 := answer("8.8.8.8", false, "9.9.9.9")
	r2.MinTTL = 30
	sel := Select("example.com", []Result{r1, r2}, isChina(chinaSet()), func(string) bool { return true })
	// override branch → only 9.9.9.9 chosen → TTL from r2
	ttl, ok := SelectTTL(sel.Addrs, []Result{r1, r2})
	if !ok || ttl != 30 {
		t.Errorf("SelectTTL = (%d, %v), want (30, true)", ttl, ok)
	}
	// first-owner wins on duplicate addresses across results
	r3 := answer("2.2.2.2", true, "1.1.1.9")
	r3.MinTTL = 10
	sel2 := Select("foo.example", []Result{r3, r1}, isChina(chinaSet()), noOverride)
	ttl2, _ := SelectTTL(sel2.Addrs, []Result{r3, r1})
	if ttl2 != 10 {
		t.Errorf("first-owner TTL = %d, want 10", ttl2)
	}
}

func assertAddrs(t *testing.T, got, want []netip.Addr) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("addrs = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("addrs = %v, want %v", got, want)
		}
	}
}
