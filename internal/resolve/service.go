// Package resolve ties the engine and cache together: one Lookup per
// (qname, qtype) goes through cache.Get, then a singleflight-coalesced
// engine.Resolve, storing only complete, authoritative results.
package resolve

import (
	"context"
	"strings"

	"github.com/miekg/dns"

	"chn-resolver/internal/cache"
	"chn-resolver/internal/engine"
)

// Service is the resolution facade used by the server.
type Service struct {
	Engine    *engine.Engine
	Cache     *cache.Cache
	CacheOn   bool
	MinTTL    uint32 // seconds
	MaxTTL    uint32
	NegMinTTL uint32
	NegMaxTTL uint32
}

// Lookup resolves (qname, qtype) via the cache and engine.
func (s *Service) Lookup(ctx context.Context, qname string, qtype uint16) (cache.Value, error) {
	key := cache.Key{Name: normalizeName(qname), QType: qtype}
	if !s.CacheOn {
		v, _ := s.resolve(ctx, qname, qtype)
		return v, nil
	}
	if v, ok := s.Cache.Get(key); ok {
		if v.TTL <= 1 {
			// sub-second leftovers are re-resolved instead of served
			s.Cache.Misses.Add(1)
		} else {
			return v, nil
		}
	}
	v, err := s.Cache.Do(ctx, key, func(ctx context.Context) (cache.Value, bool) {
		v, cacheable := s.resolve(ctx, qname, qtype)
		return v, cacheable
	})
	if err != nil {
		return cache.Value{}, err
	}
	return v, nil
}

// resolve runs the engine and converts the result into a cache value.
func (s *Service) resolve(ctx context.Context, qname string, qtype uint16) (cache.Value, bool) {
	res := s.Engine.Resolve(ctx, qname, qtype)
	if !res.Complete || res.RCode == dns.RcodeServerFailure {
		return fromEngine(res), false
	}
	if len(res.Addrs) > 0 {
		v := fromEngine(res)
		v.TTL = clamp(res.TTL, s.MinTTL, s.MaxTTL)
		return v, true
	}
	// negative: NXDOMAIN or NODATA with an SOA (FinalizeNegative only
	// returns ok=true with upstream agreement)
	if res.SOA != nil {
		v := fromEngine(res)
		neg := res.SOA.Hdr.Ttl
		if res.SOA.Minttl < neg {
			neg = res.SOA.Minttl
		}
		v.TTL = clamp(neg, s.NegMinTTL, s.NegMaxTTL)
		return v, true
	}
	return fromEngine(res), false
}

func fromEngine(res engine.Result) cache.Value {
	return cache.Value{
		RCode:  res.RCode,
		Addrs:  res.Addrs,
		SOA:    res.SOA,
		TTL:    res.TTL,
		Policy: res.Policy,
	}
}

func clamp(v, lo, hi uint32) uint32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// normalizeName lowercases and strips the trailing dot; the root becomes "".
func normalizeName(name string) string {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" {
		return "."
	}
	return n
}
