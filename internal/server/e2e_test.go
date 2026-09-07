package server_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"chn-resolver/internal/cache"
	"chn-resolver/internal/china"
	"chn-resolver/internal/config"
	"chn-resolver/internal/engine"
	"chn-resolver/internal/metrics"
	"chn-resolver/internal/overrides"
	"chn-resolver/internal/policy"
	"chn-resolver/internal/resolve"
	"chn-resolver/internal/server"
	"chn-resolver/internal/testdns"
	"chn-resolver/internal/upstream"
)

const (
	attempt = 300 * time.Millisecond
	overall = 2 * time.Second
)

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

type testEnv struct {
	svc    *resolve.Service
	srv    *server.Server
	cfg    *config.Config
	m      *metrics.Metrics
	addr   string // listen address of the server under test
	cancel context.CancelFunc
	ups    []engine.Upstream
	zones  []*testdns.Zone
}

// newEnv starts a full server on an ephemeral port with the given fake
// upstreams (the first is "china" class, the rest foreign).
func newEnv(t *testing.T, zones ...*testdns.Zone) *testEnv {
	return newEnvCfg(t, nil, zones...)
}

func newEnvCfg(t *testing.T, mut func(*config.Config), zones ...*testdns.Zone) *testEnv {
	t.Helper()
	assets := &engine.Assets{
		China: china.Build([]netip.Prefix{
			mustPrefixT(t, "1.1.1.0/24"),
			mustPrefixT(t, "2001:db8::/32"),
		}),
		Overrides: overrides.New([]string{"override.example"}, nil),
	}
	var ups []engine.Upstream
	for i, z := range zones {
		srv := testdns.StartZone(t, z)
		ups = append(ups, engine.Upstream{
			Addr:    netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(testdns.PortOf(srv.UDPAddr))),
			InChina: i == 0,
			Client:  upstream.NewClient(1232),
		})
	}
	eng := engine.New(assets, ups, attempt, 10, 1232)
	m := metrics.New([]string{})
	svc := &resolve.Service{
		Engine:    eng,
		Cache:     cache.New(1024, nil),
		CacheOn:   true,
		MinTTL:    30,
		MaxTTL:    3600,
		NegMinTTL: 60,
		NegMaxTTL: 600,
	}
	cfg := config.Defaults()
	cfg.Bind = "127.0.0.1"
	cfg.Port = 0
	cfg.OverallTimeout = overall
	cfg.AttemptTimeout = attempt
	cfg.TCPIdleTimeout = 500 * time.Millisecond
	cfg.MaxConcurrency = 32
	cfg.CacheEnabled = true
	if mut != nil {
		mut(&cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := server.New(svc, &cfg, log, m, ups)
	return &testEnv{svc: svc, srv: s, cfg: &cfg, m: m, cancel: func() {}, ups: ups, zones: zones}
}

// serve binds the server (port 0 → ephemeral) and returns its address.
func (e *testEnv) serve(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- e.srv.ListenAndServe(ctx, ready) }()
	t.Cleanup(func() {
		e.cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})
	select {
	case addr := <-ready:
		return addr
	case err := <-done:
		t.Fatalf("serve: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not come up")
	}
	return ""
}

func itoa(i int) string { return strconv.Itoa(i) }

// query sends a UDP DNS query to the server and returns the response.
func udpQuery(t *testing.T, addr string, m *dns.Msg) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("udp exchange: %v", err)
	}
	return resp
}

func tcpQuery(t *testing.T, addr string, m *dns.Msg) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("tcp exchange: %v", err)
	}
	return resp
}

func queryA(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	return m
}

func TestHappyPathUDP(t *testing.T) {
	e := newEnv(t,
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
		}},
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
		}},
	)
	addr := e.serve(t)

	resp := udpQuery(t, addr, queryA("www.example"))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if !resp.RecursionAvailable {
		t.Error("RA not set")
	}
	if !resp.RecursionDesired {
		t.Error("RD not echoed")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	rr, ok := resp.Answer[0].(*dns.A)
	if !ok || rr.A.String() != "1.1.1.9" {
		t.Fatalf("answer = %v, want A 1.1.1.9 (china preferred)", resp.Answer[0])
	}
	if rr.Hdr.Ttl != 300 {
		t.Errorf("ttl = %d, want 300", rr.Hdr.Ttl)
	}
	if rr.Hdr.Name != "www.example." {
		t.Errorf("owner = %s, want www.example.", rr.Hdr.Name)
	}
}

func TestHappyPathTCP(t *testing.T) {
	e := newEnv(t,
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
		}},
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
		}},
	)
	addr := e.serve(t)

	resp := tcpQuery(t, addr, queryA("www.example"))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("tcp: rcode %s answers %d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if resp.Answer[0].(*dns.A).A.String() != "1.1.1.9" {
		t.Errorf("tcp answer = %v", resp.Answer[0])
	}
}

func TestOverrideOnTheWire(t *testing.T) {
	e := newEnv(t,
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"override.example.": {dns.TypeA: {a("override.example.", "1.1.1.9", 300)}},
		}},
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"override.example.": {dns.TypeA: {a("override.example.", "9.9.9.9", 300)}},
		}},
	)
	addr := e.serve(t)
	resp := udpQuery(t, addr, queryA("override.example"))
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "9.9.9.9" {
		t.Fatalf("override answer = %v, want 9.9.9.9", resp.Answer)
	}
}

func TestNXDomainPropagated(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}}
	e := newEnv(t, z, z)
	addr := e.serve(t)
	resp := udpQuery(t, addr, queryA("missing.example"))
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("authority = %d, want 1 SOA", len(resp.Ns))
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority = %v, want SOA", resp.Ns[0])
	}
	// negative TTL = min(SOA Ttl 3600, Minttl 300) = 300
	if soa.Hdr.Ttl != 300 {
		t.Errorf("soa ttl = %d, want 300", soa.Hdr.Ttl)
	}
}

func TestNODATAPropagated(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeAAAA: {&dns.AAAA{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: netip.MustParseAddr("2001:db8::1").AsSlice()}}},
	}}
	e := newEnv(t, z, z)
	addr := e.serve(t)
	resp := udpQuery(t, addr, queryA("www.example"))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("rcode %s answers %d, want NOERROR/empty (NODATA)", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		t.Errorf("authority = %d, want SOA", len(resp.Ns))
	}
}

func TestForwardRelay(t *testing.T) {
	// The first (China) upstream answers TXT; our server must relay it
	// verbatim with the client's ID restored.
	cn := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"txt.example.": {dns.TypeTXT: {&dns.TXT{Hdr: dns.RR_Header{Name: "txt.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"hello"}}}},
	}}
	fg := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}}
	e := newEnv(t, cn, fg)
	addr := e.serve(t)

	m := new(dns.Msg)
	m.SetQuestion("txt.example.", dns.TypeTXT)
	resp := udpQuery(t, addr, m)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode %s answers %d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || txt.Txt[0] != "hello" {
		t.Fatalf("relayed answer = %v", resp.Answer[0])
	}
	if resp.Id != m.Id {
		t.Errorf("id = %d, want client id %d", resp.Id, m.Id)
	}
}

func TestFormErrOnNoQuestion(t *testing.T) {
	e := newEnv(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}})
	addr := e.serve(t)
	m := new(dns.Msg)
	resp := udpQuery(t, addr, m)
	if resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}

func TestSERVFAILWhenAllUpstreamsDead(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}, Delay: 2 * time.Second}
	e := newEnv(t, z, z)
	addr := e.serve(t)
	start := time.Now()
	resp := udpQuery(t, addr, queryA("www.example"))
	elapsed := time.Since(start)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if elapsed > 2*time.Second {
		t.Errorf("SERVFAIL at %v, want ~attempt timeout", elapsed)
	}
}

func TestStuckUpstreamDoesNotDelayAnswer(t *testing.T) {
	cn := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}, Delay: 2 * time.Second}
	fg := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}
	e := newEnv(t, cn, fg)
	addr := e.serve(t)
	start := time.Now()
	resp := udpQuery(t, addr, queryA("www.example"))
	elapsed := time.Since(start)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode %s answers %d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if resp.Answer[0].(*dns.A).A.String() != "9.9.9.9" {
		t.Errorf("answer = %v, want foreign 9.9.9.9", resp.Answer[0])
	}
	if elapsed > 1*time.Second {
		t.Errorf("answer at %v, want ~attempt timeout (stuck china must not delay)", elapsed)
	}
}

func TestUDPTruncationTo512WithoutOPT(t *testing.T) {
	// 40 distinct A records ≫ 512 bytes without OPT (identical records
	// would be deduped by the policy).
	recs := make([]dns.RR, 0, 40)
	for i := 1; i <= 40; i++ {
		recs = append(recs, a("big.example.", "1.1.1."+itoa(i), 300))
	}
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{"big.example.": {dns.TypeA: recs}}}
	e := newEnv(t, z, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}})
	addr := e.serve(t)

	m := queryA("big.example")
	resp := udpQuery(t, addr, m)
	if !resp.Truncated {
		t.Fatal("expected TC on oversized UDP reply without OPT")
	}
	if len(resp.Answer) == 40 {
		t.Error("reply not truncated")
	}

	// With OPT (1232) the same query should fit... 40 A records is ~640
	// bytes of answers, so it should fit without truncation.
	m2 := queryA("big.example")
	m2.SetEdns0(1232, false)
	resp2 := udpQuery(t, addr, m2)
	if resp2.Truncated {
		t.Error("unexpected TC with 1232-byte OPT")
	}
	if len(resp2.Answer) != 40 {
		t.Errorf("answers = %d, want 40", len(resp2.Answer))
	}
}

func TestTCPIdleClose(t *testing.T) {
	e := newEnv(t, &testdns.Zone{Records: map[string]map[uint16][]dns.RR{}})
	addr := e.serve(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Send a valid query, get a response, then stall.
	m := queryA("x.example")
	wire, _ := m.Pack()
	frame := make([]byte, 2+len(wire))
	frame[0] = byte(len(wire) >> 8)
	frame[1] = byte(len(wire))
	copy(frame[2:], wire)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	lb := make([]byte, 2)
	if _, err := io.ReadFull(conn, lb); err != nil {
		t.Fatalf("read length: %v", err)
	}
	resp := make([]byte, int(lb[0])<<8|int(lb[1]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	// Now stall: the server must close us after tcp_idle_timeout (500ms).
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, err = conn.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected connection close on idle")
	}
	if elapsed > 2*time.Second {
		t.Errorf("idle close at %v, want ~500ms", elapsed)
	}
}

func TestWireCoalescing(t *testing.T) {
	cn := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}}
	fg := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
	}}
	e := newEnv(t, cn, fg)
	addr := e.serve(t)

	gate := make(chan struct{})
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			<-gate
			c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			resp, _, err := c.Exchange(queryA("www.example"), addr)
			if err == nil && resp.Rcode != dns.RcodeSuccess {
				err = &errRcode{resp.Rcode}
			}
			errs <- err
		}()
	}
	close(gate)
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("query: %v", err)
		}
	}
	if cn.Hits() != 1 || fg.Hits() != 1 {
		t.Errorf("upstream hits = %d/%d, want 1/1 (coalesced)", cn.Hits(), fg.Hits())
	}
}

type errRcode struct{ rcode int }

func (e *errRcode) Error() string { return "rcode " + dns.RcodeToString[e.rcode] }

func TestOverloadDropMetric(t *testing.T) {
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}, Delay: 200 * time.Millisecond}
	e := newEnvCfg(t, func(c *config.Config) { c.MaxConcurrency = 2 }, z, z)
	addr := e.serve(t)

	// Fire 20 queries while the 2 slots are busy with slow resolutions.
	var sent atomic.Int64
	stop := make(chan struct{})
	for i := 0; i < 5; i++ {
		go func() {
			c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _, err := c.Exchange(queryA("www.example"), addr)
				if err == nil {
					sent.Add(1)
				}
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	close(stop)
	if e.m.DroppedOverload.Load() == 0 {
		t.Error("expected some overload drops")
	}
	t.Logf("sent %d, dropped %d", sent.Load(), e.m.DroppedOverload.Load())
}

func TestAAAAQuery(t *testing.T) {
	cn := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"v6.example.": {dns.TypeAAAA: {&dns.AAAA{Hdr: dns.RR_Header{Name: "v6.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: netip.MustParseAddr("2001:db8::9").AsSlice()}}},
	}}
	fg := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"v6.example.": {dns.TypeAAAA: {&dns.AAAA{Hdr: dns.RR_Header{Name: "v6.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: netip.MustParseAddr("2001:4860:4860::8888").AsSlice()}}},
	}}
	e := newEnv(t, cn, fg)
	addr := e.serve(t)

	m := new(dns.Msg)
	m.SetQuestion("v6.example.", dns.TypeAAAA)
	resp := udpQuery(t, addr, m)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode %s answers %d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if resp.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::9" {
		t.Errorf("aaaa = %v, want 2001:db8::9 (china preferred)", resp.Answer[0])
	}
}

func TestGracefulShutdownDrains(t *testing.T) {
	// An in-flight query against a delayed upstream must be allowed to
	// finish (or fail) and the server must exit within the drain window.
	z := &testdns.Zone{Records: map[string]map[uint16][]dns.RR{
		"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
	}, Delay: 200 * time.Millisecond}
	e := newEnv(t, z, z)
	addr := e.serve(t)

	respCh := make(chan *dns.Msg, 1)
	go func() {
		c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		resp, _, err := c.Exchange(queryA("www.example"), addr)
		if err != nil {
			respCh <- nil
			return
		}
		respCh <- resp
	}()
	time.Sleep(50 * time.Millisecond) // query is now in flight
	start := time.Now()
	e.cancel() // SIGTERM equivalent

	resp := <-respCh
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Errorf("in-flight query during shutdown: resp %v, want NOERROR", resp)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("shutdown took %v, want within drain window", elapsed)
	}
}

func TestPolicyMetric(t *testing.T) {
	e := newEnv(t,
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"www.example.": {dns.TypeA: {a("www.example.", "1.1.1.9", 300)}},
		}},
		&testdns.Zone{Records: map[string]map[uint16][]dns.RR{
			"www.example.": {dns.TypeA: {a("www.example.", "9.9.9.9", 300)}},
		}},
	)
	addr := e.serve(t)
	udpQuery(t, addr, queryA("www.example"))
	if e.m.Policies[policy.PolicyPreferChina].Load() != 1 {
		t.Errorf("prefer_china metric = %d, want 1", e.m.Policies[policy.PolicyPreferChina].Load())
	}
}
