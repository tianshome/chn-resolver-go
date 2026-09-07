package cache

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func posValue() Value {
	return Value{RCode: dns.RcodeSuccess, Addrs: []netip.Addr{netip.MustParseAddr("9.9.9.9")}, Policy: "p", TTL: 60}
}

func TestSetGet(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(10, clk.Now)
	c.Set(Key{Name: "www.example.com", QType: dns.TypeA}, posValue(), 60)
	v, ok := c.Get(Key{Name: "www.example.com", QType: dns.TypeA})
	if !ok || v.TTL != 60 {
		t.Fatalf("get = %+v, %v; want TTL 60", v, ok)
	}
	if c.Hits.Load() != 1 || c.Misses.Load() != 0 {
		t.Errorf("hits/misses = %d/%d", c.Hits.Load(), c.Misses.Load())
	}
}

func TestTTLCountdown(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(10, clk.Now)
	c.Set(Key{Name: "x", QType: dns.TypeA}, posValue(), 60)
	clk.Advance(10*time.Second + 500*time.Millisecond)
	v, ok := c.Get(Key{Name: "x", QType: dns.TypeA})
	if !ok || v.TTL != 50 { // ceil(49.5) = 50
		t.Fatalf("TTL = %d (%v), want 50", v.TTL, ok)
	}
}

func TestExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(10, clk.Now)
	c.Set(Key{Name: "x", QType: dns.TypeA}, posValue(), 30)
	clk.Advance(31 * time.Second)
	if _, ok := c.Get(Key{Name: "x", QType: dns.TypeA}); ok {
		t.Fatal("expired entry returned")
	}
	if c.Len() != 0 {
		t.Errorf("expired entry not removed: len %d", c.Len())
	}
}

func TestLRUEviction(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(2, clk.Now)
	k1 := Key{Name: "a", QType: dns.TypeA}
	k2 := Key{Name: "b", QType: dns.TypeA}
	k3 := Key{Name: "c", QType: dns.TypeA}
	c.Set(k1, posValue(), 60)
	c.Set(k2, posValue(), 60)
	c.Get(k1) // refresh k1 → k2 is LRU
	c.Set(k3, posValue(), 60)
	if _, ok := c.Get(k2); ok {
		t.Error("k2 should have been evicted")
	}
	if _, ok := c.Get(k1); !ok {
		t.Error("k1 should still be cached")
	}
	if _, ok := c.Get(k3); !ok {
		t.Error("k3 should be cached")
	}
}

func TestEvictExpiredFirst(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(2, clk.Now)
	c.Set(Key{Name: "a", QType: dns.TypeA}, posValue(), 10) // expires first
	clk.Advance(9 * time.Second)
	c.Set(Key{Name: "b", QType: dns.TypeA}, posValue(), 60)
	clk.Advance(2 * time.Second) // "a" now expired
	c.Set(Key{Name: "c", QType: dns.TypeA}, posValue(), 60)
	if _, ok := c.Get(Key{Name: "a", QType: dns.TypeA}); ok {
		t.Error("expired a should be gone")
	}
	if _, ok := c.Get(Key{Name: "b", QType: dns.TypeA}); !ok {
		t.Error("unexpired b should survive eviction")
	}
}

func TestFlush(t *testing.T) {
	c := New(10, nil)
	c.Set(Key{Name: "x", QType: dns.TypeA}, posValue(), 60)
	c.Flush()
	if c.Len() != 0 {
		t.Error("flush did not clear")
	}
}

func TestJanitorSweeps(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := New(10, clk.Now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunJanitor(ctx, 5*time.Millisecond)
	c.Set(Key{Name: "x", QType: dns.TypeA}, posValue(), 1)
	clk.Advance(2 * time.Second)
	deadline := time.Now().Add(time.Second)
	for c.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Len() != 0 {
		t.Error("janitor did not sweep expired entry")
	}
}

func TestDoCoalescing(t *testing.T) {
	c := New(10, nil)
	var calls atomic.Int64
	key := Key{Name: "x", QType: dns.TypeA}
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			v, err := c.Do(context.Background(), key, func(ctx context.Context) (Value, bool) {
				calls.Add(1)
				time.Sleep(50 * time.Millisecond)
				return posValue(), true
			})
			if err != nil || len(v.Addrs) != 1 {
				t.Errorf("Do: %v %+v", err, v)
			}
		}()
	}
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Errorf("fn called %d times, want 1", calls.Load())
	}
	if _, ok := c.Get(key); !ok {
		t.Error("cacheable result should be stored")
	}
}

func TestDoWaiterCtxIndependence(t *testing.T) {
	c := New(10, nil)
	key := Key{Name: "x", QType: dns.TypeA}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = c.Do(context.Background(), key, func(ctx context.Context) (Value, bool) {
			close(start)
			time.Sleep(200 * time.Millisecond)
			return posValue(), true
		})
	}()
	<-start
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := c.Do(ctx, key, func(ctx context.Context) (Value, bool) { return Value{}, false })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiter err = %v, want DeadlineExceeded", err)
	}
	wg.Wait()
	if _, ok := c.Get(key); !ok {
		t.Error("leader result should be cached despite waiter timeout")
	}
}

func TestDoNonCacheablePropagates(t *testing.T) {
	c := New(10, nil)
	key := Key{Name: "x", QType: dns.TypeA}
	v := Value{RCode: dns.RcodeServerFailure}
	got, err := c.Do(context.Background(), key, func(ctx context.Context) (Value, bool) {
		return v, false
	})
	if err != nil || got.RCode != dns.RcodeServerFailure {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, ok := c.Get(key); ok {
		t.Error("non-cacheable result must not be stored")
	}
}
