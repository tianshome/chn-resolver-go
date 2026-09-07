// Command chn-resolver is a China/foreign split-horizon DNS resolver:
// it queries multiple upstreams concurrently and picks answers with a
// China-prefix policy (with a domain override list), fronting BIND or
// other stubs on UDP and TCP.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"chn-resolver/internal/cache"
	"chn-resolver/internal/china"
	"chn-resolver/internal/config"
	"chn-resolver/internal/engine"
	"chn-resolver/internal/metrics"
	"chn-resolver/internal/overrides"
	"chn-resolver/internal/policy"
	"chn-resolver/internal/resolve"
	"chn-resolver/internal/server"
	"chn-resolver/internal/upstream"
)

var version = "dev"

const (
	defaultConfigPath = "/etc/chn-resolver/chn-resolver.toml"
	localConfigPath   = "chn-resolver.toml"
)

func main() {
	configFlag := flag.String("config", "", "path to TOML config file")
	checkFlag := flag.Bool("check", false, "load config and assets, print summary, exit")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("chn-resolver", version)
		return
	}

	cfg, err := loadConfig(*configFlag)
	if err != nil {
		fatal(err)
	}
	log := newLogger(cfg)

	assets, err := loadAssets(cfg)
	if err != nil {
		fatal(err)
	}
	engUpstreams := classifyUpstreams(cfg, assets)

	if *checkFlag {
		printSummary(cfg, assets, engUpstreams)
		return
	}

	m := metrics.New(upstreamAddrs(engUpstreams))
	eng := engine.New(assets, engUpstreams, cfg.AttemptTimeout, cfg.MaxCNAMEHops, uint16(cfg.UDPPayloadSize))
	eng.OnResult = func(idx int, state policy.State, category string) {
		m.RecordUpstreamResult(idx, state.String())
		if state == policy.StateFailure {
			m.RecordUpstreamFailure(idx, category)
		}
	}
	c := cache.New(cfg.MaxEntries, nil)
	svc := &resolve.Service{
		Engine:    eng,
		Cache:     c,
		CacheOn:   cfg.CacheEnabled,
		MinTTL:    uint32(cfg.MinTTL / time.Second),
		MaxTTL:    uint32(cfg.MaxTTL / time.Second),
		NegMinTTL: uint32(cfg.NegMinTTL / time.Second),
		NegMaxTTL: uint32(cfg.NegMaxTTL / time.Second),
	}
	srv := server.New(svc, cfg, log, m, engUpstreams)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	go c.RunJanitor(ctx, cfg.SweepInterval)
	go handleReloads(hup, cfg, log, eng, c)

	if cfg.MetricsListen != "" {
		go serveMetrics(ctx, cfg.MetricsListen, log, m)
	}

	log.Info("chn-resolver starting",
		"version", version,
		"upstreams", engUpstreams,
		"port", cfg.Port,
		"bind", cfg.Bind,
		"cache", cfg.CacheEnabled,
	)
	if err := srv.ListenAndServe(ctx, nil); err != nil && ctx.Err() == nil {
		fatal(err)
	}
	log.Info("shutdown complete")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "chn-resolver:", err)
	os.Exit(1)
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// loadConfig resolves the config path: explicit flag, then the system and
// local defaults; built-in defaults apply when no file exists.
func loadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	for _, p := range []string{defaultConfigPath, localConfigPath} {
		if _, err := os.Stat(p); err == nil {
			return config.Load(p)
		}
	}
	return nil, fmt.Errorf("no config file found (tried -config, %s, %s); prefix_files and upstreams are required — see deploy/chn-resolver.toml", defaultConfigPath, localConfigPath)
}

func loadAssets(cfg *config.Config) (*engine.Assets, error) {
	idx, err := china.Load(cfg.PrefixFiles...)
	if err != nil {
		return nil, fmt.Errorf("loading prefixes: %w", err)
	}
	var ov *overrides.Set
	if cfg.OverridesFile != "" {
		ov, err = overrides.Load(cfg.OverridesFile)
		if err != nil {
			return nil, fmt.Errorf("loading overrides: %w", err)
		}
	} else {
		ov = overrides.New(nil, nil)
	}
	return &engine.Assets{China: idx, Overrides: ov}, nil
}

// classifyUpstreams precomputes the in-China flag per upstream: explicit
// role wins, otherwise the server IP is classified against the prefix
// index (the Python behavior).
func classifyUpstreams(cfg *config.Config, assets *engine.Assets) []engine.Upstream {
	ups := make([]engine.Upstream, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		inChina := assets.China.Contains(u.Addr)
		switch u.Role {
		case config.RoleChina:
			inChina = true
		case config.RoleForeign:
			inChina = false
		}
		ups = append(ups, engine.Upstream{
			Addr:    netip.AddrPortFrom(u.Addr, uint16(u.Port)),
			InChina: inChina,
			Client:  upstream.NewClient(uint16(cfg.UDPPayloadSize)),
		})
	}
	return ups
}

func upstreamAddrs(ups []engine.Upstream) []string {
	out := make([]string, 0, len(ups))
	for _, u := range ups {
		out = append(out, u.Addr.String())
	}
	return out
}

// handleReloads swaps in freshly loaded assets on SIGHUP; on failure the
// running assets are kept and the error logged.
func handleReloads(hup <-chan os.Signal, cfg *config.Config, log *slog.Logger, eng *engine.Engine, c *cache.Cache) {
	for range hup {
		assets, err := loadAssets(cfg)
		if err != nil {
			log.Error("reload failed, keeping old assets", "err", err)
			continue
		}
		eng.UpdateAssets(assets)
		c.Flush()
		v4, v6 := assets.China.Counts()
		log.Info("assets reloaded", "v4_spans", v4, "v6_spans", v6)
	}
}

func serveMetrics(ctx context.Context, addr string, log *slog.Logger, m *metrics.Metrics) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		m.Write(w)
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Info("metrics listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("metrics server", "err", err)
	}
}

func printSummary(cfg *config.Config, assets *engine.Assets, ups []engine.Upstream) {
	v4, v6 := assets.China.Counts()
	fmt.Printf("config ok: listening on %s:%d (udp=%v tcp=%v)\n", cfg.Bind, cfg.Port, cfg.UDP, cfg.TCP)
	fmt.Printf("prefixes: %d v4 spans, %d v6 spans (inputs: %d v4, %d v6)\n", v4, v6, assets.China.V4Input, assets.China.V6Input)
	for _, u := range ups {
		fmt.Printf("upstream %s: in_china=%v\n", u.Addr, u.InChina)
	}
	fmt.Printf("timeouts: attempt=%s overall=%s; cache: enabled=%v max_entries=%d\n",
		cfg.AttemptTimeout, cfg.OverallTimeout, cfg.CacheEnabled, cfg.MaxEntries)
	fmt.Printf("ttl clamps: [%s, %s], negative [%s, %s]\n", cfg.MinTTL, cfg.MaxTTL, cfg.NegMinTTL, cfg.NegMaxTTL)
}
