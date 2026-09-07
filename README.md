# chn-resolver

A chn/elsewhere split-horizon DNS resolver in Go — a more robust,
efficient rewrite of the Python
[tianshome/chn-resolver](https://github.com/tianshome/chn_resolver).

For every A/AAAA query it fans out to all configured upstreams
concurrently, classifies returned addresses (and the upstreams
themselves) against a chn prefix list, and picks the answer with a
selection policy designed to defeat DNS pollution:

1. If a chn-class resolver returned a chn IP **and** a non-chn
   resolver returned a non-chn IP: answer from the non-chn side when
   the name is on the override list
   (`override_non_chn_from_non_chn_resolvers`), otherwise from the
   chn side (`prefer_chn_from_chn_resolvers`).
2. If nobody returned a chn IP: answer from the non-chn resolvers
   (`all_non_chn_return_only_non_chn_resolvers`).
3. Otherwise answer with chn IPs, preferring chn resolvers
   (`fallback_chn_addresses`).

Non-A/AAAA queries are relayed to the upstreams in order, with
UDP→TCP fallback on truncation. The deployed setup fronts BIND
(`forwarders { 127.0.0.1 port 8053; }`).

## Build & test

```sh
make build        # bin/chn-resolver
make test         # go test -race ./...
make vet
```

## Run

```sh
chn-resolver -config deploy/chn-resolver.toml     # serve
chn-resolver -config deploy/chn-resolver.toml -check   # validate config+assets only
chn-resolver -version
```

Configuration is TOML (see `deploy/chn-resolver.toml` for the annotated
example). With no `-config`, `/etc/chn-resolver/chn-resolver.toml` and
`./chn-resolver.toml` are tried. See `deploy/MIGRATION.md` for the
systemd cutover from the Python deployment.

## What the rewrite fixes

- **Stuck/dropped upstreams**: each upstream gets an `attempt_timeout`
  (default 1.5s) instead of one flat 2.5s wait over everything; a query
  answers as soon as the policy branch is stable (early completion) and
  is never turned into SERVFAIL by a slow straggler. All upstreams dead →
  SERVFAIL (distinct from NODATA).
- **Caching**: TTL-respecting positive cache, RFC 2308 negative caching
  (NXDOMAIN/NODATA with SOA), and singleflight coalescing — concurrent
  identical queries hit upstreams once.
- **Efficiency**: only the requested qtype is chased (the Python version
  always did A+AAAA); chn classification is a binary search over
  merged prefix ranges instead of a 32k-entry linear scan; shared
  per-upstream clients instead of a fresh socket per query.
- **Bounded intake**: concurrency cap with drop-on-overload for UDP and
  close-on-overload for TCP; TCP idle timeouts; no unbounded task
  explosion.
- **Faithful wire behavior**: NXDOMAIN/NODATA propagated with the
  upstream SOA, real TTLs, EDNS0 passthrough (DO cleared — not a DNSSEC
  endpoint), BADVERS for EDNS version > 0, TC + TCP fallback in both
  directions.
- **Operations**: slog (text/JSON), Prometheus metrics on `/metrics`,
  graceful drain on SIGTERM/SIGINT, SIGHUP reload of prefix/override
  files with cache flush (bad files keep the old assets), systemd unit
  replacing the `watch -n1` watchdog.

## Intentional divergences from the Python version

- The Python resolver chased A **and** AAAA for every query and split
  the result per type; this one chases only the requested qtype, so
  chn-classification evidence from the other address family no longer
  influences answers.
- NXDOMAIN and total upstream failure were collapsed into an empty
  NOERROR; they are now propagated faithfully (with SOA for negatives).
- CNAME targets that answer NXDOMAIN report NXDOMAIN (the Python version
  recorded an error string and returned an empty set).
- The forwarded path tries all upstreams instead of only the first.

## Layout

```
cmd/chn-resolver/   CLI entry, config discovery, signals, reload
internal/config     TOML config + validation
internal/chn      prefix loader + disjoint-range binary-search index
internal/overrides  override list matcher (exact + wildcard)
internal/policy     pure selection policy (exact _choose port) + negative finalization
internal/upstream   one-hop client (UDP→TCP on TC) + CNAME chase
internal/engine     fan-out, early completion, per-attempt deadlines
internal/cache      LRU + expiry + janitor + hand-rolled singleflight
internal/resolve    service facade (cache → flight → engine → store)
internal/server     bounded UDP/TCP intake, dispatch, synthesis, forwarder
internal/metrics    Prometheus text counters
```

## Notes

- Not a DNSSEC endpoint: outbound queries clear DO and answers carry no
  RRSIGs. Fine behind BIND with `dnssec-validation no`; a DO-aware mode
  would need the DO bit in the cache key.
- `chnroute.txt` is a different, v4-only dataset and is not supported as
  input (see `assets/README.md`).
