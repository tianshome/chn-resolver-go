# Migration: Python multiresolver → Go chn-resolver

The live deployment today (2026-09-07):

- BIND `named.service` listens on :53 and forwards globally to
  `127.0.0.1 port 8053` (`/etc/bind/named.conf.options`, `dnssec-validation no`).
- The Python multiresolver listens on `127.0.0.1:8053`, kept alive by
  `watch -n 1 sudo bash ~/resolver.sh` (running as root, pids 417756/417757,
  respawning the `uv run multiresolver` process).

BIND needs **no changes**: chn-resolver binds the same 127.0.0.1:8053.

## Cutover

```sh
cd /home/ubuntu/chn-resolver
make build && sudo make install   # binary + /etc/chn-resolver/chn-resolver.toml + unit

# Verify the config and assets load (no listeners touched):
chn-resolver -config /etc/chn-resolver/chn-resolver.toml -check

# Start the service (binds 8053 — the Python process still holds it, so
# stop the watchdog FIRST if you are not replacing it in this order):
sudo systemctl enable --now chn-resolver
systemctl status chn-resolver
ss -ulpn | grep 8053            # expect chn-resolver, not python
```

**Important:** stop the old watchdog only after the unit holds the port.
The old process tree is `watch -n 1 sudo bash ~/resolver.sh` on pts/10.
Ctrl-C that terminal, or kill the `watch` parents (pids above) — then make
sure no `python3 .../multiresolver` process survives (`pkill -f 'bin/multiresolver'`
as root if needed). Do **not** run both on 8053 at once.

## Smoke test

```sh
dig @127.0.0.1 -p 8053 wx.qq.com A          # China CDN → China IP from the CN resolver
dig @127.0.0.1 -p 8053 github.com A         # foreign → non-China IPs
dig @127.0.0.1 -p 8053 www.linkedin.com A   # override list → foreign answer
dig @127.0.0.1 -p 8053 no-such-name-xyz.example A   # NXDOMAIN + SOA (new behavior)
curl -s localhost:8055/metrics               # if metrics enabled
```

## Reload assets without restart

```sh
sudo systemctl reload chn-resolver   # SIGHUP: swaps prefix/override files, flushes cache
```

On a bad file the old assets are kept and the error is logged — the
resolver never goes down over a bad edit (unlike the Python version, where
a crash mid-edit was masked by the watch loop).

## Rollback

```sh
sudo systemctl stop chn-resolver
# and re-run the old watchdog:  watch -n 1 sudo bash ~/resolver.sh
```

## Behavior changes to expect (all intentional)

| Python | chn-resolver |
|---|---|
| A/AAAA queries always chased both types | only the requested type is chased |
| NXDOMAIN/errors → empty NOERROR | NXDOMAIN/NODATA propagated with SOA; all-upstream failure → SERVFAIL |
| fixed TTL 60 on every answer | real upstream TTLs, clamped 30s–3600s; negative caching per RFC 2308 (60s–600s) |
| every query re-queried upstreams | TTL cache + singleflight coalescing |
| slow upstream delayed/killed the query (flat 2.5s) | per-upstream attempt timeout; answers as soon as the policy allows |
| non-A/AAAA relayed only to upstreams[0] | tried against all upstreams in order |
| unbounded per-packet tasks, TCP stalls forever | bounded concurrency (drop on overload), 30s TCP idle close |
| crash recovery via `watch -n1` | systemd `Restart=on-failure` + SIGHUP reload |
