package authzen

import (
	"context"
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

// key canonically encodes a request, without the context keys that vary
// per request (such as request_id).
func (c *permitCache) key(req EvaluationRequest) ([sha256.Size]byte, bool) {
	return requestKey(req, c.ignoreKeys)
}

// requestKey canonically encodes a request. encoding/json writes struct
// fields in declaration order and map keys sorted, so equal requests encode
// equally. Context keys in ignore are dropped.
func requestKey(req EvaluationRequest, ignore map[string]struct{}) ([sha256.Size]byte, bool) {
	if len(ignore) > 0 {
		ctx := make(Context, len(req.Context))
		for k, v := range req.Context {
			if _, skip := ignore[k]; !skip {
				ctx[k] = v
			}
		}
		req.Context = ctx
	}
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

// decisionMemo remembers every decision made for one incoming request, so a
// request that asks the same question twice reaches the PDP once.
type decisionMemo struct {
	mu        sync.Mutex
	decisions map[[sha256.Size]byte]bool
}

type decisionMemoKey struct{}

// WithDecisionMemo returns a context in which Evaluate answers identical
// requests once. It remembers denials as well as permits, so create one per
// incoming request and never let it outlive that request. Failed
// evaluations are not remembered.
func WithDecisionMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, decisionMemoKey{}, &decisionMemo{decisions: map[[sha256.Size]byte]bool{}})
}

func memoFrom(ctx context.Context) *decisionMemo {
	m, _ := ctx.Value(decisionMemoKey{}).(*decisionMemo)
	return m
}

func (m *decisionMemo) lookup(req EvaluationRequest) (decision, ok bool) {
	if m == nil {
		return false, false
	}
	k, ok := requestKey(req, nil)
	if !ok {
		return false, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	decision, ok = m.decisions[k]
	return decision, ok
}

func (m *decisionMemo) store(req EvaluationRequest, decision bool) {
	if m == nil {
		return
	}
	if k, ok := requestKey(req, nil); ok {
		m.mu.Lock()
		m.decisions[k] = decision
		m.mu.Unlock()
	}
}
