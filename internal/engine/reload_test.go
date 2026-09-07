package engine_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"chn-resolver/internal/china"
	"chn-resolver/internal/engine"
	"chn-resolver/internal/overrides"
	"chn-resolver/internal/policy"
	"chn-resolver/internal/testdns"
)

// TestUpdateAssetsSwap verifies a SIGHUP-style asset swap changes
// classification on the next query.
func TestUpdateAssetsSwap(t *testing.T) {
	assets1 := &engine.Assets{
		China:     china.Build([]netip.Prefix{mustPrefixT(t, "1.1.1.0/24")}),
		Overrides: overrides.New(nil, nil),
	}
	cn, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}}, true)
	fg, _ := upstreamFromZone(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}, false)
	e := engine.New(assets1, []engine.Upstream{cn, fg}, attempt, maxHops, udpSize)

	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()
	res := e.Resolve(ctx, "www.example", dns.TypeA)
	if res.Policy != policy.PolicyPreferChina {
		t.Fatalf("policy before swap = %q, want prefer_china", res.Policy)
	}

	// After the swap, 1.1.1.9 is no longer classified China: the China
	// resolver now yields no China IPs → rule 2 (foreign IPs).
	e.UpdateAssets(&engine.Assets{
		China:     china.Build([]netip.Prefix{mustPrefixT(t, "2.2.2.0/24")}),
		Overrides: overrides.New(nil, nil),
	})
	ctx2, cancel2 := context.WithTimeout(context.Background(), overall)
	defer cancel2()
	res2 := e.Resolve(ctx2, "www.example", dns.TypeA)
	if res2.Policy != policy.PolicyAllNonChina || len(res2.Addrs) != 1 || res2.Addrs[0] != netip.MustParseAddr("9.9.9.9") {
		t.Fatalf("after swap: policy %q addrs %v, want all_non_china [9.9.9.9]", res2.Policy, res2.Addrs)
	}
}
