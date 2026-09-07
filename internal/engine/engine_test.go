package engine_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/china"
	"chn-resolver/internal/engine"
	"chn-resolver/internal/overrides"
	"chn-resolver/internal/policy"
	"chn-resolver/internal/testdns"
	"chn-resolver/internal/upstream"
)

const (
	attempt = 300 * time.Millisecond
	overall = 2 * time.Second
	maxHops = 10
	udpSize = 1232
	fast    = 0 * time.Millisecond
	stuck   = 2 * time.Second
)

func mustPrefixT(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p.Masked()
}

func testAssets(t *testing.T) *engine.Assets {
	t.Helper()
	return &engine.Assets{
		China:     china.Build([]netip.Prefix{mustPrefixT(t, "1.1.1.0/24"), mustPrefixT(t, "2001:db8::/32")}),
		Overrides: overrides.New([]string{"override.example"}, nil),
	}
}

// upstreamFromZone wires a fake server as an engine upstream.
func upstreamFromZone(t *testing.T, z *testdns.Zone, inChina bool) (engine.Upstream, *testdns.Server) {
	t.Helper()
	srv := testdns.StartZone(t, z)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(testdns.PortOf(srv.UDPAddr)))
	return engine.Upstream{
		Addr:    addr,
		InChina: inChina,
		Client:  upstream.NewClient(udpSize),
	}, srv
}

func a(name, ip string, ttl uint32) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: netip.MustParseAddr(ip).AsSlice()}
}

func newEngine(t *testing.T, ups ...engine.Upstream) *engine.Engine {
	t.Helper()
	return engine.New(testAssets(t), ups, attempt, maxHops, udpSize)
}

func TestPreferChinaBothFast(t *testing.T) {
	cn, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}}, true)
	fg, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}, false)

	e := newEngine(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	res := e.Resolve(ctx, "www.example", dns.TypeA)

	if res.RCode != dns.RcodeSuccess || res.Policy != policy.PolicyPreferChina {
		t.Errorf("rcode/policy = %d/%q, want success/prefer_china", res.RCode, res.Policy)
	}
	if len(res.Addrs) != 1 || res.Addrs[0] != netip.MustParseAddr("1.1.1.9") {
		t.Errorf("addrs = %v, want [1.1.1.9]", res.Addrs)
	}
	if !res.Complete {
		t.Error("Complete = false, want true")
	}
}

func TestOverridePrefersForeign(t *testing.T) {
	cn, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"override.example.": {dns.TypeA: {a("override.example.", "1.1.1.9", 300)}},
	}}, true)
	fg, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"override.example.": {dns.TypeA: {a("override.example.", "9.9.9.9", 300)}},
	}}, false)

	e := newEngine(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	res := e.Resolve(ctx, "override.example", dns.TypeA)

	if res.Policy != policy.PolicyOverride || len(res.Addrs) != 1 || res.Addrs[0] != netip.MustParseAddr("9.9.9.9") {
		t.Errorf("policy/addrs = %q/%v, want override/[9.9.9.9]", res.Policy, res.Addrs)
	}
}

// The core stuck-upstream fix: a dead China side must not delay or kill a
// query the foreign side answered instantly.
func TestStuckChinaForeignAnswersAtAttemptTimeout(t *testing.T) {
	cnZone := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}, Delay: stuck}
	fgZone := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}, Delay: fast}
	cn, _ := upstreamFromZone(t, cnZone, true)
	fg, _ := upstreamFromZone(t, fgZone, false)

	e := newEngine(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	start := time.Now()
	res := e.Resolve(ctx, "www.example", dns.TypeA)
	elapsed := time.Since(start)

	if res.RCode != dns.RcodeSuccess || res.Policy != policy.PolicyAllNonChina {
		t.Errorf("rcode/policy = %d/%q, want success/all_non_china", res.RCode, res.Policy)
	}
	if len(res.Addrs) != 1 || res.Addrs[0] != netip.MustParseAddr("9.9.9.9") {
		t.Errorf("addrs = %v, want [9.9.9.9]", res.Addrs)
	}
	if !res.Complete {
		t.Error("Complete = false; all upstreams reported (china = failure), want true")
	}
	if elapsed > time.Second {
		t.Errorf("answer took %v, want ~attempt timeout (%v)", elapsed, attempt)
	}
	if elapsed < 200*time.Millisecond {
		t.Errorf("answer at %v; expected to wait out the stuck upstream (~%v)", elapsed, attempt)
	}
}

func TestAllStuckSERVFAIL(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}, Delay: stuck}
	cn, _ := upstreamFromZone(t, z, true)
	fg, _ := upstreamFromZone(t, z, false)

	e := newEngine(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	start := time.Now()
	res := e.Resolve(ctx, "www.example", dns.TypeA)
	elapsed := time.Since(start)

	if res.RCode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL", res.RCode)
	}
	if elapsed > time.Second {
		t.Errorf("SERVFAIL at %v, want ~attempt timeout", elapsed)
	}
}

// Rule-1 early completion: with 2 fast results deciding the branch, a slow
// third upstream must not delay the answer (which is also not cached).
func TestEarlyCompletionWithSlowStraggler(t *testing.T) {
	cn, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}}, true)
	fgFast, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}, false)
	fgSlow, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "8.8.4.4", 300)}},
	}, Delay: stuck}, false)

	e := newEngine(t, cn, fgFast, fgSlow)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	start := time.Now()
	res := e.Resolve(ctx, "www.example", dns.TypeA)
	elapsed := time.Since(start)

	if res.RCode != dns.RcodeSuccess || res.Policy != policy.PolicyPreferChina {
		t.Errorf("rcode/policy = %d/%q, want success/prefer_china", res.RCode, res.Policy)
	}
	if res.Complete {
		t.Error("Complete = true; answered before the slow straggler finished, want false")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("early answer took %v, want << straggler delay", elapsed)
	}
}

func TestBothNXDomain(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}}
	cn, _ := upstreamFromZone(t, z, true)
	fg, _ := upstreamFromZone(t, z, false)

	e := newEngine(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	res := e.Resolve(ctx, "missing.example", dns.TypeA)

	if res.RCode != dns.RcodeNameError || res.SOA == nil {
		t.Errorf("rcode/soa = %d/%v, want NXDOMAIN with SOA", res.RCode, res.SOA)
	}
	if !res.Complete {
		t.Error("Complete = false, want true")
	}
}

func TestNXDomainPlusStuck(t *testing.T) {
	cn, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}}, true)
	fg, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"missing.example.": {dns.TypeA: {a("missing.example.", "9.9.9.9", 300)}},
	}, Delay: stuck}, false)

	e := newEngine(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	start := time.Now()
	res := e.Resolve(ctx, "missing.example", dns.TypeA)
	elapsed := time.Since(start)

	// The stuck upstream fails at attempt timeout, leaving one NXDOMAIN
	// among failures → NXDOMAIN.
	if res.RCode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN", res.RCode)
	}
	if elapsed > time.Second {
		t.Errorf("NXDOMAIN at %v, want ~attempt timeout", elapsed)
	}
}

func TestCNAMEFanOut(t *testing.T) {
	cn, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"foo.example.":   {dns.TypeA: {cname("foo.example.", "alias.example.")}},
		"alias.example.": {dns.TypeA: {a("alias.example.", "1.1.1.9", 300)}},
	}}, true)
	fg, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"foo.example.":   {dns.TypeA: {cname("foo.example.", "alias.example.")}},
		"alias.example.": {dns.TypeA: {a("alias.example.", "9.9.9.9", 300)}},
	}}, false)

	e := newEngine(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	res := e.Resolve(ctx, "foo.example", dns.TypeA)

	if res.RCode != dns.RcodeSuccess || len(res.Addrs) != 1 || res.Addrs[0] != netip.MustParseAddr("1.1.1.9") {
		t.Errorf("rcode/addrs = %d/%v, want success/[1.1.1.9]", res.RCode, res.Addrs)
	}
}

func cname(name, target string) dns.RR {
	return &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: target}
}
