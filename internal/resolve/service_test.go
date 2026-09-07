package resolve

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/cache"
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
)

func testService(t *testing.T, ups ...engine.Upstream) *Service {
	t.Helper()
	assets := &engine.Assets{
		China:     china.Build([]netip.Prefix{mustPrefixT(t, "1.1.1.0/24")}),
		Overrides: overrides.New(nil, nil),
	}
	return &Service{
		Engine:    engine.New(assets, ups, attempt, 10, 1232),
		Cache:     cache.New(1024, nil),
		CacheOn:   true,
		MinTTL:    30,
		MaxTTL:    3600,
		NegMinTTL: 60,
		NegMaxTTL: 600,
	}
}

func mustPrefixT(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix: %v", err)
	}
	return p.Masked()
}

func a(name, ip string, ttl uint32) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: netip.MustParseAddr(ip).AsSlice()}
}

func zoneUpstream(t *testing.T, z *testdns.Zone, inChina bool) engine.Upstream {
	t.Helper()
	srv := testdns.StartZone(t, z)
	return engine.Upstream{
		Addr:    netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(testdns.PortOf(srv.UDPAddr))),
		InChina: inChina,
		Client:  upstream.NewClient(1232),
	}
}

func TestLookupPositiveCached(t *testing.T) {
	cn := zoneUpstream(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}}, true)
	fg := zoneUpstream(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}, false)
	svc := testService(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()

	v, err := svc.Lookup(ctx, "www.example", dns.TypeA)
	if err != nil || v.RCode != dns.RcodeSuccess || len(v.Addrs) != 1 {
		t.Fatalf("lookup: %+v, %v", v, err)
	}
	if v.TTL != 300 {
		t.Errorf("TTL = %d, want 300", v.TTL)
	}
	if v.Policy != policy.PolicyPreferChina {
		t.Errorf("policy = %q", v.Policy)
	}
	if svc.Cache.Hits.Load() != 0 || svc.Cache.Misses.Load() != 1 {
		t.Errorf("hits/misses = %d/%d, want 0/1", svc.Cache.Hits.Load(), svc.Cache.Misses.Load())
	}

	// second lookup must come from cache
	v2, err := svc.Lookup(ctx, "www.example", dns.TypeA)
	if err != nil || v2.Addrs[0] != v.Addrs[0] {
		t.Fatalf("cached lookup: %+v, %v", v2, err)
	}
	if svc.Cache.Hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", svc.Cache.Hits.Load())
	}
	if v2.TTL > 300 || v2.TTL < 299 {
		t.Errorf("cached TTL = %d, want ~300", v2.TTL)
	}
}

func TestLookupTTLClamp(t *testing.T) {
	cn := zoneUpstream(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 5)}},
	}}, true)
	fg := zoneUpstream(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 5)}},
	}}, false)
	svc := testService(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	v, err := svc.Lookup(ctx, "www.example", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if v.TTL != 30 {
		t.Errorf("TTL = %d, want clamped to min 30", v.TTL)
	}
}

func TestLookupNegativeCachedWithSOATTL(t *testing.T) {
	// SOA: Ttl 3600, Minttl 300 → negative TTL 300 (within [60, 600])
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}}
	cn := zoneUpstream(t, z, true)
	fg := zoneUpstream(t, z, false)
	svc := testService(t, cn, fg)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()

	v, err := svc.Lookup(ctx, "missing.example", dns.TypeA)
	if err != nil || v.RCode != dns.RcodeNameError || v.SOA == nil {
		t.Fatalf("lookup: %+v, %v", v, err)
	}
	if v.TTL != 300 {
		t.Errorf("negative TTL = %d, want 300 (min(3600, 300))", v.TTL)
	}
	if _, ok := svc.Cache.Get(cache.Key{Name: "missing.example", QType: dns.TypeA}); !ok {
		t.Error("NXDOMAIN should be negatively cached")
	}
}

func TestLookupNonCacheablePartial(t *testing.T) {
	// Rule-1 early completion (Complete=false) must not be cached: use a
	// slow third upstream so the engine early-returns.
	cn := zoneUpstream(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}}, true)
	fg := zoneUpstream(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}, false)
	slow := zoneUpstream(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "8.8.4.4", 300)}},
	}, Delay: 2 * time.Second}, false)
	svc := testService(t, cn, fg, slow)
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()

	v, err := svc.Lookup(ctx, "www.example", dns.TypeA)
	if err != nil || len(v.Addrs) != 1 {
		t.Fatalf("lookup: %+v, %v", v, err)
	}
	if _, ok := svc.Cache.Get(cache.Key{Name: "www.example", QType: dns.TypeA}); ok {
		t.Error("partial (Complete=false) result must not be cached")
	}
}

func TestLookupWireCoalescing(t *testing.T) {
	cnZone := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}}
	fgZone := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}
	svc := testService(t, zoneUpstream(t, cnZone, true), zoneUpstream(t, fgZone, false))
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()

	gate := make(chan struct{})
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			<-gate
			_, err := svc.Lookup(ctx, "www.example", dns.TypeA)
			errs <- err
		}()
	}
	close(gate)
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if cnZone.Hits() != 1 || fgZone.Hits() != 1 {
		t.Errorf("upstream hits = %d/%d, want 1/1 (coalesced)", cnZone.Hits(), fgZone.Hits())
	}
}
