package authzen

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"
)

// permitCache remembers permit decisions for a short TTL. Denials and
// errors are never stored, so a revoked permission takes effect at most
// one TTL later while a newly granted one takes effect immediately.
type permitCache struct {
	ttl        time.Duration
	maxEntries int
	ignoreKeys map[string]struct{}
	now        func() time.Time

	mu      sync.Mutex
	entries map[[sha256.Size]byte]time.Time
}

func newPermitCache(ttl time.Duration, maxEntries int, ignoreContextKeys []string, now func() time.Time) *permitCache {
	if ttl <= 0 {
		return nil
	}
	ignore := make(map[string]struct{}, len(ignoreContextKeys))
	for _, k := range ignoreContextKeys {
		ignore[k] = struct{}{}
	}
	return &permitCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		ignoreKeys: ignore,
		now:        now,
		entries:    make(map[[sha256.Size]byte]time.Time),
	}
}

// key canonically encodes a request. encoding/json writes struct fields in
// declaration order and map keys sorted, so equal requests encode equally.
// Context keys that vary per request (such as request_id) are dropped.
func (c *permitCache) key(req EvaluationRequest) ([sha256.Size]byte, bool) {
	ctx := make(Context, len(req.Context))
	for k, v := range req.Context {
		if _, skip := c.ignoreKeys[k]; !skip {
			ctx[k] = v
		}
	}
	req.Context = ctx
	raw, err := json.Marshal(req)
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256(raw), true
}

func (c *permitCache) permitted(req EvaluationRequest) bool {
	if c == nil {
		return false
	}
	k, ok := c.key(req)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.entries[k]
	if !ok {
		return false
	}
	if !c.now().Before(exp) {
		delete(c.entries, k)
		return false
	}
	return true
}

func (c *permitCache) storePermit(req EvaluationRequest) {
	if c == nil {
		return
	}
	k, ok := c.key(req)
	if !ok {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		for ek, exp := range c.entries {
			if !now.Before(exp) {
				delete(c.entries, ek)
			}
		}
		if len(c.entries) >= c.maxEntries {
			// Still full of live entries: start over rather than grow unbounded.
			c.entries = make(map[[sha256.Size]byte]time.Time)
		}
	}
	c.entries[k] = now.Add(c.ttl)
}
