package config

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/BurntSushi/toml"
)

// raw is the on-disk TOML shape; strings are converted and validated into Config.
type raw struct {
	Bind           string        `toml:"bind"`
	Port           int           `toml:"port"`
	UDP            *bool         `toml:"udp"`
	TCP            *bool         `toml:"tcp"`
	TCPIdleTimeout string        `toml:"tcp_idle_timeout"`
	MaxConcurrency int           `toml:"max_concurrency"`
	Upstreams      []rawUpstream `toml:"upstream"`
	China          rawChina      `toml:"china"`
	Resolve        rawResolve    `toml:"resolve"`
	Cache          rawCache      `toml:"cache"`
	Forward        rawForward    `toml:"forward"`
	Log            rawLog        `toml:"log"`
	Metrics        rawMetrics    `toml:"metrics"`
}

type rawUpstream struct {
	Addr string `toml:"addr"`
	Port int    `toml:"port"`
	Role string `toml:"role"`
}

type rawChina struct {
	PrefixFiles   []string `toml:"prefix_files"`
	OverridesFile string   `toml:"overrides_file"`
}

type rawResolve struct {
	OverallTimeout string `toml:"overall_timeout"`
	AttemptTimeout string `toml:"attempt_timeout"`
	MaxCNAMEHops   int    `toml:"max_cname_hops"`
	UDPPayloadSize int    `toml:"udp_payload_size"`
	MinTTL         string `toml:"min_ttl"`
	MaxTTL         string `toml:"max_ttl"`
	NegMinTTL      string `toml:"neg_min_ttl"`
	NegMaxTTL      string `toml:"neg_max_ttl"`
}

type rawCache struct {
	Enabled       *bool  `toml:"enabled"`
	MaxEntries    int    `toml:"max_entries"`
	SweepInterval string `toml:"sweep_interval"`
}

type rawForward struct {
	Timeout string `toml:"timeout"`
}

type rawLog struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

type rawMetrics struct {
	Listen string `toml:"listen"`
}

// Role of an upstream in the selection policy.
type Role int

const (
	RoleAuto Role = iota // classify by prefix index (Python behavior)
	RoleChina
	RoleForeign
)

type Upstream struct {
	Addr netip.Addr
	Port int
	Role Role
}

func (u Upstream) String() string {
	return netip.AddrPortFrom(u.Addr, uint16(u.Port)).String()
}

type Config struct {
	Bind           string
	Port           int
	UDP            bool
	TCP            bool
	TCPIdleTimeout time.Duration
	MaxConcurrency int

	Upstreams []Upstream

	PrefixFiles   []string
	OverridesFile string

	OverallTimeout time.Duration
	AttemptTimeout time.Duration
	MaxCNAMEHops   int
	UDPPayloadSize int
	MinTTL         time.Duration
	MaxTTL         time.Duration
	NegMinTTL      time.Duration
	NegMaxTTL      time.Duration

	CacheEnabled  bool
	MaxEntries    int
	SweepInterval time.Duration

	ForwardTimeout time.Duration

	LogLevel  string
	LogFormat string

	MetricsListen string
}

func Defaults() Config {
	return Config{
		Bind:           "127.0.0.1",
		Port:           8053,
		UDP:            true,
		TCP:            true,
		TCPIdleTimeout: 30 * time.Second,
		MaxConcurrency: 512,

		OverallTimeout: 2500 * time.Millisecond,
		AttemptTimeout: 1500 * time.Millisecond,
		MaxCNAMEHops:   10,
		UDPPayloadSize: 1232,
		MinTTL:         30 * time.Second,
		MaxTTL:         3600 * time.Second,
		NegMinTTL:      60 * time.Second,
		NegMaxTTL:      600 * time.Second,

		CacheEnabled:  true,
		MaxEntries:    65536,
		SweepInterval: 30 * time.Second,

		ForwardTimeout: 2500 * time.Millisecond,

		LogLevel:  "info",
		LogFormat: "text",
	}
}

// Load reads, decodes, validates, and converts the TOML file at path.
func Load(path string) (*Config, error) {
	var r raw
	if _, err := toml.DecodeFile(path, &r); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return r.build()
}

// FromBytes decodes config from TOML bytes (used by tests).
func FromBytes(data []byte) (*Config, error) {
	var r raw
	if err := toml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return r.build()
}

func (r raw) build() (*Config, error) {
	c := Defaults()

	if r.Bind != "" {
		c.Bind = r.Bind
	}
	if r.Port != 0 {
		if r.Port < 1 || r.Port > 65535 {
			return nil, fmt.Errorf("port must be 1-65535, got %d", r.Port)
		}
		c.Port = r.Port
	}
	if r.UDP != nil {
		c.UDP = *r.UDP
	}
	if r.TCP != nil {
		c.TCP = *r.TCP
	}
	if !c.UDP && !c.TCP {
		return nil, fmt.Errorf("at least one of udp or tcp must be enabled")
	}
	var err error
	if r.TCPIdleTimeout != "" {
		if c.TCPIdleTimeout, err = time.ParseDuration(r.TCPIdleTimeout); err != nil {
			return nil, fmt.Errorf("tcp_idle_timeout: %w", err)
		}
	}
	if r.MaxConcurrency != 0 {
		if r.MaxConcurrency < 1 {
			return nil, fmt.Errorf("max_concurrency must be >= 1")
		}
		c.MaxConcurrency = r.MaxConcurrency
	}

	for i, u := range r.Upstreams {
		addr, err := netip.ParseAddr(u.Addr)
		if err != nil {
			return nil, fmt.Errorf("upstream[%d].addr %q: %w", i, u.Addr, err)
		}
		up := Upstream{Addr: addr, Port: 53, Role: RoleAuto}
		if u.Port != 0 {
			if u.Port < 1 || u.Port > 65535 {
				return nil, fmt.Errorf("upstream[%d].port must be 1-65535, got %d", i, u.Port)
			}
			up.Port = u.Port
		}
		switch u.Role {
		case "", "auto":
		case "china":
			up.Role = RoleChina
		case "foreign":
			up.Role = RoleForeign
		default:
			return nil, fmt.Errorf("upstream[%d].role must be auto|china|foreign, got %q", i, u.Role)
		}
		c.Upstreams = append(c.Upstreams, up)
	}
	if len(c.Upstreams) < 1 {
		return nil, fmt.Errorf("at least one upstream resolver is required")
	}
	seen := map[netip.Addr]bool{}
	for _, u := range c.Upstreams {
		if seen[u.Addr] {
			return nil, fmt.Errorf("duplicate upstream address %s", u.Addr)
		}
		seen[u.Addr] = true
	}

	c.PrefixFiles = append([]string(nil), r.China.PrefixFiles...)
	if len(c.PrefixFiles) == 0 {
		return nil, fmt.Errorf("china.prefix_files must list at least one prefix file")
	}
	c.OverridesFile = r.China.OverridesFile

	if r.Resolve.OverallTimeout != "" {
		if c.OverallTimeout, err = time.ParseDuration(r.Resolve.OverallTimeout); err != nil {
			return nil, fmt.Errorf("resolve.overall_timeout: %w", err)
		}
	}
	if r.Resolve.AttemptTimeout != "" {
		if c.AttemptTimeout, err = time.ParseDuration(r.Resolve.AttemptTimeout); err != nil {
			return nil, fmt.Errorf("resolve.attempt_timeout: %w", err)
		}
	}
	if c.AttemptTimeout > c.OverallTimeout {
		return nil, fmt.Errorf("resolve.attempt_timeout (%s) must be <= resolve.overall_timeout (%s)", c.AttemptTimeout, c.OverallTimeout)
	}
	if r.Resolve.MaxCNAMEHops != 0 {
		if r.Resolve.MaxCNAMEHops < 1 || r.Resolve.MaxCNAMEHops > 64 {
			return nil, fmt.Errorf("resolve.max_cname_hops must be 1-64")
		}
		c.MaxCNAMEHops = r.Resolve.MaxCNAMEHops
	}
	if r.Resolve.UDPPayloadSize != 0 {
		if r.Resolve.UDPPayloadSize < 512 || r.Resolve.UDPPayloadSize > 4096 {
			return nil, fmt.Errorf("resolve.udp_payload_size must be 512-4096")
		}
		c.UDPPayloadSize = r.Resolve.UDPPayloadSize
	}
	if r.Resolve.MinTTL != "" {
		if c.MinTTL, err = time.ParseDuration(r.Resolve.MinTTL); err != nil {
			return nil, fmt.Errorf("resolve.min_ttl: %w", err)
		}
	}
	if r.Resolve.MaxTTL != "" {
		if c.MaxTTL, err = time.ParseDuration(r.Resolve.MaxTTL); err != nil {
			return nil, fmt.Errorf("resolve.max_ttl: %w", err)
		}
	}
	if c.MinTTL > c.MaxTTL {
		return nil, fmt.Errorf("resolve.min_ttl must be <= resolve.max_ttl")
	}
	if r.Resolve.NegMinTTL != "" {
		if c.NegMinTTL, err = time.ParseDuration(r.Resolve.NegMinTTL); err != nil {
			return nil, fmt.Errorf("resolve.neg_min_ttl: %w", err)
		}
	}
	if r.Resolve.NegMaxTTL != "" {
		if c.NegMaxTTL, err = time.ParseDuration(r.Resolve.NegMaxTTL); err != nil {
			return nil, fmt.Errorf("resolve.neg_max_ttl: %w", err)
		}
	}
	if c.NegMinTTL > c.NegMaxTTL {
		return nil, fmt.Errorf("resolve.neg_min_ttl must be <= resolve.neg_max_ttl")
	}

	if r.Cache.Enabled != nil {
		c.CacheEnabled = *r.Cache.Enabled
	}
	if r.Cache.MaxEntries != 0 {
		if r.Cache.MaxEntries < 1 {
			return nil, fmt.Errorf("cache.max_entries must be >= 1")
		}
		c.MaxEntries = r.Cache.MaxEntries
	}
	if r.Cache.SweepInterval != "" {
		if c.SweepInterval, err = time.ParseDuration(r.Cache.SweepInterval); err != nil {
			return nil, fmt.Errorf("cache.sweep_interval: %w", err)
		}
	}

	if r.Forward.Timeout != "" {
		if c.ForwardTimeout, err = time.ParseDuration(r.Forward.Timeout); err != nil {
			return nil, fmt.Errorf("forward.timeout: %w", err)
		}
	}

	switch r.Log.Level {
	case "":
	case "debug", "info", "warn", "error":
		c.LogLevel = r.Log.Level
	default:
		return nil, fmt.Errorf("log.level must be debug|info|warn|error, got %q", r.Log.Level)
	}
	switch r.Log.Format {
	case "":
	case "text", "json":
		c.LogFormat = r.Log.Format
	default:
		return nil, fmt.Errorf("log.format must be text|json, got %q", r.Log.Format)
	}

	if r.Metrics.Listen != "" {
		if _, err := netip.ParseAddrPort(r.Metrics.Listen); err != nil {
			return nil, fmt.Errorf("metrics.listen %q: %w", r.Metrics.Listen, err)
		}
		c.MetricsListen = r.Metrics.Listen
	}
	return &c, nil
}
