package cache

import "context"

// flight coalesces concurrent identical lookups: the first caller runs fn,
// the rest wait for its result. A waiter whose own context expires first
// gets its ctx error immediately — no shared fate beyond the flight.
type flight struct {
	done chan struct{}
	v    Value
}

// Do runs fn once per key. fn returns the value and whether it is
// cacheable; cacheable values are stored automatically. Waiters receive
// the leader's value even when it is not cacheable.
func (c *Cache) Do(ctx context.Context, key Key, fn func(ctx context.Context) (Value, bool)) (Value, error) {
	c.mu.Lock()
	if f, ok := c.flights[key]; ok {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.v, nil
		case <-ctx.Done():
			return Value{}, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	c.flights[key] = f
	c.mu.Unlock()

	v, cacheable := fn(ctx)

	c.mu.Lock()
	f.v = v
	delete(c.flights, key)
	if cacheable {
		c.setLocked(key, v)
	}
	c.mu.Unlock()
	close(f.done)
	return v, nil
}
