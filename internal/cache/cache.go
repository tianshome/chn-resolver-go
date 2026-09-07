// Package cache provides a TTL-respecting LRU cache with negative caching
// and in-flight query coalescing (singleflight).
package cache

import (
	"container/list"
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Key identifies a cached resolution. Name is normalized: lowercase,
// trailing dot stripped ("" means the root). Only A/AAAA queries reach
// the cache.
type Key struct {
	Name  string
	QType uint16
}

// Value is a cached resolution result. TTL is the serving TTL baseline in
// seconds; remaining lifetime is recomputed at read time from Expires.
type Value struct {
	RCode   int
	Addrs   []netip.Addr
	SOA     *dns.SOA // negative entries only
	TTL     uint32
	Policy  string
	Expires time.Time
}

// IsNegative reports whether the value is an NXDOMAIN/NODATA entry.
func (v Value) IsNegative() bool { return len(v.Addrs) == 0 && v.RCode != dns.RcodeServerFailure }

type entry struct {
	key   Key
	value Value
}

// Cache is an LRU with lazy expiry and a background janitor.
type Cache struct {
	mu         sync.Mutex
	maxEntries int
	ll         *list.List // front = most recently used
	items      map[Key]*list.Element
	flights    map[Key]*flight
	now        func() time.Time

	Hits, Misses, Evictions atomic.Int64
}

// New creates a cache. now is injectable for tests (nil = time.Now).
func New(maxEntries int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{
		maxEntries: maxEntries,
		ll:         list.New(),
		items:      make(map[Key]*list.Element),
		flights:    make(map[Key]*flight),
		now:        now,
	}
}

// Get returns the value if present and unexpired, moving it to the MRU
// front. The returned TTL is the remaining lifetime in seconds.
func (c *Cache) Get(key Key) (Value, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.Misses.Add(1)
		return Value{}, false
	}
	v := el.Value.(*entry).value
	remaining := v.Expires.Sub(c.now())
	if remaining <= 0 {
		c.remove(el)
		c.Evictions.Add(1)
		c.Misses.Add(1)
		return Value{}, false
	}
	v.TTL = uint32((remaining + time.Second - 1) / time.Second) // ceil to whole seconds
	c.ll.MoveToFront(el)
	c.Hits.Add(1)
	return v, true
}

// Set stores a value with the given TTL (seconds).
func (c *Cache) Set(key Key, v Value, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v.TTL = ttl
	c.setLocked(key, v)
}

// setLocked computes expiry from v.TTL, inserts or replaces, and evicts as
// needed. Caller holds mu.
func (c *Cache) setLocked(key Key, v Value) {
	v.Expires = c.now().Add(time.Duration(v.TTL) * time.Second)
	if el, ok := c.items[key]; ok {
		el.Value.(*entry).value = v
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&entry{key: key, value: v})
	c.items[key] = el
	c.evictLocked()
}

// evictLocked removes expired entries first, then the LRU tail, until the
// cache is within capacity.
func (c *Cache) evictLocked() {
	for c.ll.Len() > c.maxEntries {
		// scan from the back (LRU end); expired entries are likely there
		var victim *list.Element
		for el := c.ll.Back(); el != nil; el = el.Prev() {
			if !el.Value.(*entry).value.Expires.After(c.now()) {
				victim = el
				break
			}
		}
		if victim == nil {
			victim = c.ll.Back()
		}
		c.remove(victim)
		c.Evictions.Add(1)
	}
}

func (c *Cache) remove(el *list.Element) {
	e := el.Value.(*entry)
	delete(c.items, e.key)
	c.ll.Remove(el)
}

// Len returns the current number of entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Flush drops all entries (asset reload invalidates classifications).
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = make(map[Key]*list.Element)
}

// RunJanitor periodically sweeps expired entries until ctx is done.
func (c *Cache) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.sweep()
		}
	}
}

func (c *Cache) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for el := c.ll.Back(); el != nil; {
		prev := el.Prev()
		if !el.Value.(*entry).value.Expires.After(now) {
			c.remove(el)
			c.Evictions.Add(1)
		}
		el = prev
	}
}
