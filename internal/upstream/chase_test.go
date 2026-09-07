package upstream_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/policy"
	"chn-resolver/internal/testdns"
	"chn-resolver/internal/upstream"
)

func a(name, ip string, ttl uint32) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: netip.MustParseAddr(ip).AsSlice()}
}

func cname(name, target string) dns.RR {
	return &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: target}
}

func chase(t *testing.T, z *testdns.Zone, qname string, qtype uint16, attempt time.Duration) policy.Result {
	t.Helper()
	srv := testdns.StartZone(t, z)
	cl := upstream.NewClient(1232)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(testdns.PortOf(srv.UDPAddr)))
	return upstream.Chase(ctx, cl, addr, qname, qtype, 10, attempt, 1232)
}

// Port of test_cname_recursion_resolves_targets (single-type variant).
func TestChaseCNAMEChain(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"foo.example.":    {dns.TypeA: {cname("foo.example.", "alias1.example.")}},
		"alias1.example.": {dns.TypeA: {cname("alias1.example.", "alias2.example.")}},
		"alias2.example.": {dns.TypeA: {a("alias2.example.", "1.1.1.9", 300)}},
	}}
	res := chase(t, z, "foo.example", dns.TypeA, time.Second)
	if res.State != policy.StateAnswer {
		t.Fatalf("state = %v (%s), want answer", res.State, res.ErrCategory)
	}
	if len(res.Addrs) != 1 || res.Addrs[0] != netip.MustParseAddr("1.1.1.9") {
		t.Errorf("addrs = %v, want [1.1.1.9]", res.Addrs)
	}
}

// A pure CNAME loop terminates via the seen guard (Python parity: no
// records, no error) rather than the depth cap.
func TestChaseCNAMELoopTerminates(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"a.example.": {dns.TypeA: {cname("a.example.", "b.example.")}},
		"b.example.": {dns.TypeA: {cname("b.example.", "a.example.")}},
	}}
	res := chase(t, z, "a.example", dns.TypeA, time.Second)
	if res.State != policy.StateNoData {
		t.Errorf("state = %v (%s), want nodata", res.State, res.ErrCategory)
	}
}

// A chain longer than the hop cap fails with cname-maxdepth.
func TestChaseCNAMELongChainCapped(t *testing.T) {
	recs := map[string]map[uint16][]dns.RR{}
	for i := 1; i <= 12; i++ {
		recs[fmt.Sprintf("a%d.example.", i)] = map[uint16][]dns.RR{
			dns.TypeA: {cname(fmt.Sprintf("a%d.example.", i), fmt.Sprintf("a%d.example.", i+1))},
		}
	}
	recs["a13.example."] = map[uint16][]dns.RR{dns.TypeA: {a("a13.example.", "1.1.1.9", 300)}}
	z := &testdns.Zone{Records: recs}
	res := chase(t, z, "a1.example", dns.TypeA, time.Second)
	if res.State != policy.StateFailure || res.ErrCategory != "cname-maxdepth" {
		t.Errorf("state = %v (%s), want failure cname-maxdepth", res.State, res.ErrCategory)
	}
}

func TestChaseNXDomainCarriesSOA(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}}
	res := chase(t, z, "missing.example", dns.TypeA, time.Second)
	if res.State != policy.StateNXDomain || res.SOA == nil {
		t.Errorf("state = %v, soa = %v; want nxdomain with SOA", res.State, res.SOA)
	}
}

func TestChaseNoData(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeAAAA: {&dns.AAAA{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: netip.MustParseAddr("2001:db8::1").AsSlice()}}},
	}}
	res := chase(t, z, "www.example", dns.TypeA, time.Second)
	if res.State != policy.StateNoData || res.SOA == nil {
		t.Errorf("state = %v, soa = %v; want nodata with SOA", res.State, res.SOA)
	}
}

func TestChaseTCFallbackToTCP(t *testing.T) {
	z := &testdns.Zone{
		Records:     map[string]map[uint16][]dns.RR{"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}}},
		TruncateUDP: true,
	}
	res := chase(t, z, "www.example", dns.TypeA, time.Second)
	if res.State != policy.StateAnswer || len(res.Addrs) != 1 {
		t.Errorf("state = %v (%s) addrs = %v; want answer via TCP", res.State, res.ErrCategory, res.Addrs)
	}
}

func TestChaseTimeout(t *testing.T) {
	z := &testdns.Zone{
		Records: map[string]map[uint16][]dns.RR{"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}}},
		Delay:   2 * time.Second,
	}
	start := time.Now()
	res := chase(t, z, "www.example", dns.TypeA, 200*time.Millisecond)
	elapsed := time.Since(start)
	if res.State != policy.StateFailure || res.ErrCategory != "timeout" {
		t.Errorf("state = %v (%s), want failure timeout", res.State, res.ErrCategory)
	}
	if elapsed > time.Second {
		t.Errorf("timeout took %v, want ~200ms", elapsed)
	}
}

func TestChaseFullChainInOneMessage(t *testing.T) {
	// Custom handler returning CNAME + target A in a single answer.
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer,
			cname("foo.example.", "alias.example."),
			a("alias.example.", "1.2.3.4", 300),
		)
		_ = w.WriteMsg(m)
	})
	srv := testdns.Start(t, handler)
	cl := upstream.NewClient(1232)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(testdns.PortOf(srv.UDPAddr)))
	res := upstream.Chase(ctx, cl, addr, "foo.example", dns.TypeA, 10, time.Second, 1232)
	if res.State != policy.StateAnswer || len(res.Addrs) != 1 || res.Addrs[0] != netip.MustParseAddr("1.2.3.4") {
		t.Errorf("state = %v addrs = %v, want single-hop answer [1.2.3.4]", res.State, res.Addrs)
	}
}

func TestChaseMinTTL(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {
			a("www.example.", "9.9.9.9", 600),
			a("www.example.", "8.8.4.4", 60),
		}},
	}}
	res := chase(t, z, "www.example", dns.TypeA, time.Second)
	if res.State != policy.StateAnswer || res.MinTTL != 60 {
		t.Errorf("state = %v minTTL = %d, want answer with minTTL 60", res.State, res.MinTTL)
	}
}
