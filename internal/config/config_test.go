package config

import (
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	c := Defaults()
	if c.Port != 8053 || !c.UDP || !c.TCP {
		t.Errorf("bad listener defaults: %+v", c)
	}
	if c.MaxConcurrency != 512 || c.AttemptTimeout != 1500*time.Millisecond || c.OverallTimeout != 2500*time.Millisecond {
		t.Errorf("bad timeout defaults: %+v", c)
	}
}

func TestMinimalValid(t *testing.T) {
	c, err := FromBytes([]byte(`
[[upstream]]
addr = "202.96.209.133"
[[upstream]]
addr = "8.8.8.8"

[china]
prefix_files = ["/tmp/x.txt"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Upstreams) != 2 || c.Upstreams[0].Port != 53 || c.Upstreams[0].Role != RoleAuto {
		t.Errorf("bad upstreams: %+v", c.Upstreams)
	}
	if c.Bind != "127.0.0.1" || c.CacheEnabled != true || c.MaxEntries != 65536 {
		t.Errorf("defaults not applied: %+v", c)
	}
}

func TestFullOverride(t *testing.T) {
	c, err := FromBytes([]byte(`
bind = "::"
port = 8054
udp = true
tcp = false
tcp_idle_timeout = "10s"
max_concurrency = 100

[[upstream]]
addr = "202.96.209.133"
port = 5300
role = "china"
[[upstream]]
addr = "8.8.8.8"
role = "foreign"

[china]
prefix_files = ["/a", "/b"]
overrides_file = "/o"

[resolve]
overall_timeout = "3s"
attempt_timeout = "1s"
max_cname_hops = 5
udp_payload_size = 1400
min_ttl = "10s"
max_ttl = "300s"
neg_min_ttl = "5s"
neg_max_ttl = "60s"

[cache]
enabled = false
max_entries = 1000
sweep_interval = "5s"

[forward]
timeout = "2s"

[log]
level = "debug"
format = "json"

[metrics]
listen = "127.0.0.1:9999"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Bind != "::" || c.Port != 8054 || c.TCP || !c.UDP {
		t.Errorf("bad listener: %+v", c)
	}
	if c.TCPIdleTimeout != 10*time.Second || c.MaxConcurrency != 100 {
		t.Errorf("bad tcp/concurrency: %+v", c)
	}
	if c.Upstreams[0].Role != RoleChina || c.Upstreams[1].Role != RoleForeign || c.Upstreams[0].Port != 5300 {
		t.Errorf("bad upstreams: %+v", c.Upstreams)
	}
	if len(c.PrefixFiles) != 2 || c.OverridesFile != "/o" {
		t.Errorf("bad china: %+v", c)
	}
	if c.OverallTimeout != 3*time.Second || c.AttemptTimeout != 1*time.Second || c.MaxCNAMEHops != 5 || c.UDPPayloadSize != 1400 {
		t.Errorf("bad resolve: %+v", c)
	}
	if c.CacheEnabled || c.MaxEntries != 1000 || c.SweepInterval != 5*time.Second {
		t.Errorf("bad cache: %+v", c)
	}
	if c.ForwardTimeout != 2*time.Second || c.LogLevel != "debug" || c.LogFormat != "json" || c.MetricsListen != "127.0.0.1:9999" {
		t.Errorf("bad forward/log/metrics: %+v", c)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{"no upstreams", `[china]` + "\nprefix_files = [\"/x\"]"},
		{"bad addr", "[[upstream]]\naddr = \"not-an-ip\"\n\n[china]\nprefix_files = [\"/x\"]"},
		{"bad role", "[[upstream]]\naddr = \"1.1.1.1\"\nrole = \"mars\"\n\n[china]\nprefix_files = [\"/x\"]"},
		{"dup upstream", "[[upstream]]\naddr = \"1.1.1.1\"\n[[upstream]]\naddr = \"1.1.1.1\"\n\n[china]\nprefix_files = [\"/x\"]"},
		{"no prefix files", "[[upstream]]\naddr = \"1.1.1.1\""},
		{"attempt > overall", "[[upstream]]\naddr = \"1.1.1.1\"\n\n[china]\nprefix_files = [\"/x\"]\n\n[resolve]\noverall_timeout = \"1s\"\nattempt_timeout = \"2s\""},
		{"min > max ttl", "[[upstream]]\naddr = \"1.1.1.1\"\n\n[china]\nprefix_files = [\"/x\"]\n\n[resolve]\nmin_ttl = \"10s\"\nmax_ttl = \"1s\""},
		{"bad level", "[[upstream]]\naddr = \"1.1.1.1\"\n\n[china]\nprefix_files = [\"/x\"]\n\n[log]\nlevel = \"loud\""},
		{"udp+tcp off", "udp = false\ntcp = false\n[[upstream]]\naddr = \"1.1.1.1\"\n\n[china]\nprefix_files = [\"/x\"]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := FromBytes([]byte(c.toml)); err == nil {
				t.Errorf("expected validation error for %q", c.name)
			}
		})
	}
}
