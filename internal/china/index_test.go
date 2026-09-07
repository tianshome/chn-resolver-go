package china

import (
	"math/rand"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p.Masked()
}

func naiveContains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func TestContainsMatchesNaive(t *testing.T) {
	prefixes := []netip.Prefix{
		mustPrefix(t, "1.0.1.0/24"),
		mustPrefix(t, "1.0.2.0/23"),
		mustPrefix(t, "10.0.0.0/8"),
		mustPrefix(t, "2001:4860::/32"),
		mustPrefix(t, "2400:3200::/32"),
		mustPrefix(t, "::ffff:192.168.1.0/120"),
	}
	// overlapping + duplicate to exercise merge
	prefixes = append(prefixes,
		mustPrefix(t, "1.0.2.128/25"),
		mustPrefix(t, "10.1.0.0/16"),
		mustPrefix(t, "1.0.1.0/24"),
	)
	ix := Build(prefixes)

	testIPs := []string{
		"1.0.1.0", "1.0.1.255", "1.0.2.0", "1.0.2.200", "1.0.3.255",
		"10.0.0.1", "10.255.255.255", "11.0.0.0", "9.255.255.255",
		"8.8.8.8", "202.96.209.133", "0.0.0.0", "255.255.255.255",
		"2001:4860:4860::8888", "2001:4860:ffff::1", "2001:4861::1",
		"2400:3200:baba::1", "2400:3201::1", "::1", "::",
		"192.168.1.5", "192.168.2.1",
	}
	for _, s := range testIPs {
		ip := netip.MustParseAddr(s)
		got := ix.Contains(ip)
		want := naiveContains(prefixes, ip)
		if got != want {
			t.Errorf("Contains(%s) = %v, naive says %v", s, got, want)
		}
	}

	rng := rand.New(rand.NewSource(42))
	var v4, v6 int
	for i := 0; i < 20000; i++ {
		var ip netip.Addr
		if i%2 == 0 {
			ip = netip.AddrFrom4([4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
			v4++
		} else {
			var b [16]byte
			rng.Read(b[:])
			ip = netip.AddrFrom16(b)
			v6++
		}
		if got, want := ix.Contains(ip), naiveContains(prefixes, ip); got != want {
			t.Fatalf("Contains(%s) = %v, naive says %v", ip, got, want)
		}
	}
	t.Logf("random check: %d v4, %d v6", v4, v6)
}

func TestSpanBoundaries(t *testing.T) {
	ix := Build([]netip.Prefix{
		mustPrefix(t, "10.20.30.0/24"),
		mustPrefix(t, "fd00::/120"),
	})
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.20.29.255", false},
		{"10.20.30.0", true},
		{"10.20.30.255", true},
		{"10.20.31.0", false},
		{"fd00::", true},
		{"fd00::ff", true},
		{"fd00::100", false},
		{"fd00::1:0", false},
	}
	for _, c := range cases {
		if got := ix.Contains(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestAdjacentMerge(t *testing.T) {
	ix := Build([]netip.Prefix{
		mustPrefix(t, "10.0.0.0/25"),
		mustPrefix(t, "10.0.0.128/25"),
	})
	v4, _ := ix.Counts()
	if v4 != 1 {
		t.Errorf("adjacent prefixes should merge to 1 span, got %d", v4)
	}
	if !ix.Contains(netip.MustParseAddr("10.0.0.200")) {
		t.Error("10.0.0.200 should be contained after merge")
	}
}

func TestParsePrefixLine(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		want string // expected masked prefix, empty if !ok
	}{
		{"1.0.1.0/24", true, "1.0.1.0/24"},
		{"  1.0.1.0/24  ", true, "1.0.1.0/24"},
		{"# comment", false, ""},
		{"; comment", false, ""},
		{"// comment", false, ""},
		{"", false, ""},
		{"   ", false, ""},
		{"1.0.1.0/24 # inline", true, "1.0.1.0/24"},
		{"1.0.1.0/24\t;inline", true, "1.0.1.0/24"},
		{"1.0.1.0/24 //inline", true, "1.0.1.0/24"},
		{"1.2.3.4/24", true, "1.2.3.0/24"}, // host bits masked, strict=False parity
		{"2001:db8::1/32", true, "2001:db8::/32"},
		{"not-a-prefix", true, ""}, // err case: ok irrelevant, error expected
	}
	for _, c := range cases {
		p, ok, err := ParsePrefixLine(c.line)
		if c.line == "not-a-prefix" {
			if err == nil {
				t.Errorf("ParsePrefixLine(%q): expected error", c.line)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePrefixLine(%q): unexpected error %v", c.line, err)
			continue
		}
		if ok != c.ok {
			t.Errorf("ParsePrefixLine(%q): ok = %v, want %v", c.line, ok, c.ok)
			continue
		}
		if ok && p.String() != c.want {
			t.Errorf("ParsePrefixLine(%q) = %s, want %s", c.line, p, c.want)
		}
	}
}

func TestLoadRealAssetFile(t *testing.T) {
	const path = "/home/ubuntu/multiresolver/assets/chn_prefixes.txt"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("asset file not available: %v", err)
	}
	ix, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The split files each carry 6 header lines, so 9538/22893 raw lines
	// correspond to 9532 v4 + 22887 v6 actual prefixes (verified against
	// the Python parser).
	if ix.V4Input != 9532 || ix.V6Input != 22887 {
		t.Errorf("input counts = %d v4 / %d v6, want 9532 / 22887", ix.V4Input, ix.V6Input)
	}
	for _, ip := range []string{"202.96.209.133", "114.114.114.114", "1.0.1.0"} {
		if !ix.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("%s should be classified in-China", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "2001:4860:4860::8888"} {
		if ix.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("%s should NOT be classified in-China", ip)
		}
	}
}

func TestLoadFrom(t *testing.T) {
	ix, err := LoadFrom(strings.NewReader("10.0.0.0/8\n192.168.0.0/16 # comment\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !ix.Contains(netip.MustParseAddr("10.1.2.3")) || !ix.Contains(netip.MustParseAddr("192.168.9.9")) {
		t.Error("expected both prefixes loaded")
	}
	if ix.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Error("11.0.0.1 outside /8")
	}
}
