# Assets

chn-resolver consumes two data files (paths configured in the TOML):

- `chn_prefixes.txt` — IP2Location "China" firewall list, combined
  v4+v6. Format: one CIDR per line, blank lines and `#`, `;`, `//`
  comments (whole-line or inline after whitespace) ignored; host bits
  masked. The split variants `chn_prefixes_v4.txt` / `chn_prefixes_v6.txt`
  are accepted too (the combined file is exactly their concatenation).
  The deployed copy lives in `/home/ubuntu/multiresolver/assets/`.
  The list header says "update every month" — the deployed copy is from
  2025-12-27.

- `override_domains.txt` — domains whose answers must come from the
  non-China resolvers even when the China side answered. One entry per
  line: exact names (`bing.com`) and wildcards (`*.apple.com`, matching
  any subdomain but not the apex). Deployed: linkedin.com, *.linkedin.com,
  *.apple.com, *.apple-mapkit.com, *.akadns.net, bing.com, *.bing.com.

## Not used: chnroute.txt

`/home/ubuntu/chnroute.txt` is a **different, IPv4-only** dataset (8,607
lines) and is NOT a substitute for `chn_prefixes.txt` (9,532 v4 + 22,887
v6 prefixes). Do not point `prefix_files` at it.
