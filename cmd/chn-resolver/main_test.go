package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"chn-resolver/internal/china"
	"chn-resolver/internal/config"
	"chn-resolver/internal/engine"
	"chn-resolver/internal/overrides"
)

func TestClassifyUpstreams(t *testing.T) {
	assets := &engine.Assets{
		China:     china.Build([]netip.Prefix{mustPrefix(t, "1.1.1.0/24")}),
		Overrides: overrides.New(nil, nil),
	}
	cfg := config.Defaults()
	cfg.Upstreams = []config.Upstream{
		{Addr: netip.MustParseAddr("1.1.1.1"), Port: 53}, // auto → in prefix list
		{Addr: netip.MustParseAddr("8.8.8.8"), Port: 53}, // auto → not in list
		{Addr: netip.MustParseAddr("9.9.9.9"), Port: 53, Role: config.RoleChina},
		{Addr: netip.MustParseAddr("114.114.114.114"), Port: 53, Role: config.RoleForeign},
	}
	ups := classifyUpstreams(&cfg, assets)
	want := []bool{true, false, true, false}
	for i, w := range want {
		if ups[i].InChina != w {
			t.Errorf("upstream %d inChina = %v, want %v", i, ups[i].InChina, w)
		}
	}
	if ups[0].Addr.Port() != 53 {
		t.Errorf("default port = %d, want 53", ups[0].Addr.Port())
	}
}

func TestLoadAssetsFromFiles(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "prefixes.txt")
	if err := os.WriteFile(prefix, []byte("1.1.1.0/24\n2001:db8::/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ov := filepath.Join(dir, "overrides.txt")
	if err := os.WriteFile(ov, []byte("linkedin.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.PrefixFiles = []string{prefix}
	cfg.OverridesFile = ov
	assets, err := loadAssets(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !assets.China.Contains(netip.MustParseAddr("1.1.1.9")) ||
		!assets.China.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("prefixes not loaded")
	}
	if !assets.Overrides.Match("linkedin.com") {
		t.Error("override not loaded")
	}
}

func TestLoadAssetsFailsOnMissingFile(t *testing.T) {
	cfg := config.Defaults()
	cfg.PrefixFiles = []string{"/nonexistent/prefixes.txt"}
	if _, err := loadAssets(&cfg); err == nil {
		t.Error("expected error for missing prefix file")
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p.Masked()
}
