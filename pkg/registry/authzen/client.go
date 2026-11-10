package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// WellKnownPath is the AuthZEN metadata path, appended to the PDP base URL.
const WellKnownPath = "/.well-known/authzen-configuration"

const (
	defaultTimeout          = 1500 * time.Millisecond
	defaultMaxResponseBytes = 4 << 20
	defaultCacheMaxEntries  = 10000
	maxSearchPages          = 10000
	// discoveryRetryAfter is how long a failed discovery is reported to
	// callers before the PDP is asked again.
	discoveryRetryAfter = time.Second
)

var (
	// ErrUnavailable wraps every failure to obtain a decision: transport
	// errors, timeouts, non-2xx responses, malformed bodies and failed
	// discovery. Callers must treat it as a denial.
	ErrUnavailable = errors.New("authzen: pdp unavailable")
	// ErrDiscovery reports invalid or mismatched PDP metadata.
	ErrDiscovery = errors.New("authzen: discovery failed")
	// ErrSearchNotSupported reports that the PDP does not advertise
	// search_resource_endpoint.
	ErrSearchNotSupported = errors.New("authzen: resource search not supported by pdp")
	// ErrTooManyResults reports a search that returned more results than
	// the caller allowed.
	ErrTooManyResults = errors.New("authzen: too many search results")
)

// Config configures a Client.
type Config struct {
	// BaseURL is the PDP identifier; metadata is discovered from
	// BaseURL + WellKnownPath and its policy_decision_point must match.
	BaseURL string
	// HTTPClient is used for every PDP call; nil uses a new http.Client.
	HTTPClient *http.Client
	// Timeout bounds each PDP call (default 1.5s).
	Timeout time.Duration
	// CacheTTL caches permit decisions; 0 disables the cache.
	CacheTTL time.Duration
	// CacheMaxEntries bounds the permit cache (default 10000).
	CacheMaxEntries int
	// CacheIgnoreContextKeys are context members left out of the cache key
	// because they vary per request (default: request_id).
	CacheIgnoreContextKeys []string
	// TokenSource authenticates the PEP to the PDP; nil sends no token.
	TokenSource TokenSource
	// MaxResponseBytes caps a PDP response body (default 4 MiB).
	MaxResponseBytes int64
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Client is an AuthZEN 1.0 PEP client. It is safe for concurrent use.
type Client struct {
	base     *url.URL
	baseNorm string
	http     *http.Client
	timeout  time.Duration
	tokens   TokenSource
	maxBytes int64
	cache    *permitCache
	now      func() time.Time

	// discovery runs at most once at a time, shared by concurrent callers.
	discovery singleflight.Group

	// mu guards the fields below; it is never held across a PDP call.
	mu        sync.Mutex
	meta      *Metadata
	failedAt  time.Time
	failedErr error
}

// New validates cfg and returns a Client. Discovery happens lazily on the
// first call, so the PDP need not be reachable at startup.
func New(cfg Config) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("authzen: invalid base URL %q", cfg.BaseURL)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return nil, fmt.Errorf("authzen: unsupported base URL scheme %q", base.Scheme)
	}
	c := &Client{
		base:     base,
		baseNorm: normalizeURL(base.String()),
		http:     cfg.HTTPClient,
		timeout:  cfg.Timeout,
		tokens:   cfg.TokenSource,
		maxBytes: cfg.MaxResponseBytes,
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	if c.maxBytes <= 0 {
		c.maxBytes = defaultMaxResponseBytes
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	maxEntries := cfg.CacheMaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultCacheMaxEntries
	}
	ignore := cfg.CacheIgnoreContextKeys
	if ignore == nil {
		ignore = []string{"request_id"}
	}
	c.now = now
	c.cache = newPermitCache(cfg.CacheTTL, maxEntries, ignore, now)
	return c, nil
}

func normalizeURL(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

// Metadata returns the PDP metadata, discovering it when not cached.
// Concurrent callers share one discovery, and each stops waiting when its
// own context ends. A failed discovery is reported for discoveryRetryAfter
// before the PDP is asked again.
func (c *Client) Metadata(ctx context.Context) (Metadata, error) {
	c.mu.Lock()
	if c.meta != nil {
		meta := *c.meta
		c.mu.Unlock()
		return meta, nil
	}
	if c.failedErr != nil && c.now().Sub(c.failedAt) < discoveryRetryAfter {
		err := c.failedErr
		c.mu.Unlock()
		return Metadata{}, err
	}
	c.mu.Unlock()

	// The shared discovery must outlive any one caller's cancellation; it is
	// still bounded by the client timeout inside do.
	result := c.discovery.DoChan("discover", func() (any, error) {
		meta, err := c.discover(context.WithoutCancel(ctx))
		c.mu.Lock()
		defer c.mu.Unlock()
		if err != nil {
			c.failedAt, c.failedErr = c.now(), err
			return nil, err
		}
		c.meta, c.failedErr = &meta, nil
		return meta, nil
	})
	select {
	case <-ctx.Done():
		return Metadata{}, fmt.Errorf("%w: discovery: %w", ErrUnavailable, ctx.Err())
	case r := <-result:
		if r.Err != nil {
			return Metadata{}, r.Err
		}
		return r.Val.(Metadata), nil
	}
}

// invalidate drops cached metadata so the next call re-discovers.
func (c *Client) invalidate() {
	c.mu.Lock()
	c.meta = nil
	c.mu.Unlock()
}

func (c *Client) discover(ctx context.Context) (Metadata, error) {
	var meta Metadata
	endpoint := strings.TrimRight(c.base.String(), "/") + WellKnownPath
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &meta); err != nil {
		return Metadata{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	if normalizeURL(meta.PolicyDecisionPoint) != c.baseNorm {
		return Metadata{}, fmt.Errorf("%w: %w: policy_decision_point %q does not match configured %q",
			ErrUnavailable, ErrDiscovery, meta.PolicyDecisionPoint, c.baseNorm)
	}
	if meta.AccessEvaluationEndpoint == "" {
		return Metadata{}, fmt.Errorf("%w: %w: access_evaluation_endpoint is missing", ErrUnavailable, ErrDiscovery)
	}
	for _, ep := range []*string{
		&meta.AccessEvaluationEndpoint, &meta.AccessEvaluationsEndpoint,
		&meta.SearchSubjectEndpoint, &meta.SearchResourceEndpoint, &meta.SearchActionEndpoint,
	} {
		if *ep == "" {
			continue
		}
		u, err := url.Parse(*ep)
		if err != nil {
			return Metadata{}, fmt.Errorf("%w: %w: invalid endpoint %q", ErrUnavailable, ErrDiscovery, *ep)
		}
		*ep = c.base.ResolveReference(u).String()
	}
	return meta, nil
}

// SupportsResourceSearch reports whether the PDP advertises
// search_resource_endpoint.
func (c *Client) SupportsResourceSearch(ctx context.Context) (bool, error) {
	meta, err := c.Metadata(ctx)
	if err != nil {
		return false, err
	}
	return meta.SearchResourceEndpoint != "", nil
}

// Evaluate asks for one decision. Permits are served from and stored in
// the cache; denials and errors are not cached. With WithDecisionMemo, a
// request repeated within the same incoming request is answered from the
// memo, denials included.
func (c *Client) Evaluate(ctx context.Context, req EvaluationRequest) (EvaluationResponse, error) {
	memo := memoFrom(ctx)
	if decision, ok := memo.lookup(req); ok {
		return EvaluationResponse{Decision: decision}, nil
	}
	if c.cache.permitted(req) {
		return EvaluationResponse{Decision: true}, nil
	}
	meta, err := c.Metadata(ctx)
	if err != nil {
		return EvaluationResponse{}, err
	}
	var resp EvaluationResponse
	if err := c.post(ctx, meta.AccessEvaluationEndpoint, req, &resp); err != nil {
		return EvaluationResponse{}, err
	}
	memo.store(req, resp.Decision)
	if resp.Decision {
		c.cache.storePermit(req)
	}
	return resp, nil
}

// Evaluations asks for a batch of decisions. When every item is a cached
// permit the PDP is not called. When the PDP does not advertise
// access_evaluations_endpoint the batch is evaluated item by item with the
// requested semantic.
func (c *Client) Evaluations(ctx context.Context, req EvaluationsRequest) (EvaluationsResponse, error) {
	n := len(req.Evaluations)
	if n == 0 {
		return EvaluationsResponse{Evaluations: []EvaluationResponse{}}, nil
	}
	items := make([]EvaluationRequest, n)
	allCached := c.cache != nil
	for i := range req.Evaluations {
		item, err := req.Expand(i)
		if err != nil {
			return EvaluationsResponse{}, err
		}
		items[i] = item
		if allCached && !c.cache.permitted(item) {
			allCached = false
		}
	}
	if allCached {
		out := make([]EvaluationResponse, n)
		for i := range out {
			out[i].Decision = true
		}
		return EvaluationsResponse{Evaluations: out}, nil
	}

	meta, err := c.Metadata(ctx)
	if err != nil {
		return EvaluationsResponse{}, err
	}
	if meta.AccessEvaluationsEndpoint == "" {
		return c.evaluateSequentially(ctx, req.Semantic(), items)
	}
	var resp EvaluationsResponse
	if err := c.post(ctx, meta.AccessEvaluationsEndpoint, req, &resp); err != nil {
		return EvaluationsResponse{}, err
	}
	if err := checkBatchShape(req.Semantic(), n, resp.Evaluations); err != nil {
		return EvaluationsResponse{}, err
	}
	for i, d := range resp.Evaluations {
		if d.Decision {
			c.cache.storePermit(items[i])
		}
	}
	return resp, nil
}

func (c *Client) evaluateSequentially(ctx context.Context, sem EvaluationsSemantic, items []EvaluationRequest) (EvaluationsResponse, error) {
	out := make([]EvaluationResponse, 0, len(items))
	for _, item := range items {
		d, err := c.Evaluate(ctx, item)
		if err != nil {
			return EvaluationsResponse{}, err
		}
		out = append(out, d)
		if (sem == DenyOnFirstDeny && !d.Decision) || (sem == PermitOnFirstPermit && d.Decision) {
			break
		}
	}
	return EvaluationsResponse{Evaluations: out}, nil
}

// checkBatchShape rejects a batch response that cannot belong to the
// request: execute_all must answer every item; a short-circuit semantic may
// stop early only on its stopping decision.
func checkBatchShape(sem EvaluationsSemantic, n int, got []EvaluationResponse) error {
	if len(got) == 0 || len(got) > n {
		return fmt.Errorf("%w: batch of %d returned %d decisions", ErrUnavailable, n, len(got))
	}
	if len(got) == n {
		return nil
	}
	last := got[len(got)-1].Decision
	switch {
	case sem == DenyOnFirstDeny && !last, sem == PermitOnFirstPermit && last:
		return nil
	default:
		return fmt.Errorf("%w: %s batch of %d returned %d decisions", ErrUnavailable, sem, n, len(got))
	}
}

// SearchResource fetches one page of resource search results.
func (c *Client) SearchResource(ctx context.Context, req ResourceSearchRequest) (ResourceSearchResponse, error) {
	meta, err := c.Metadata(ctx)
	if err != nil {
		return ResourceSearchResponse{}, err
	}
	if meta.SearchResourceEndpoint == "" {
		return ResourceSearchResponse{}, ErrSearchNotSupported
	}
	var resp ResourceSearchResponse
	if err := c.post(ctx, meta.SearchResourceEndpoint, req, &resp); err != nil {
		return ResourceSearchResponse{}, err
	}
	return resp, nil
}

// SearchResources follows next_token until the last page and returns every
// result. max > 0 fails with ErrTooManyResults once more results arrive.
func (c *Client) SearchResources(ctx context.Context, req ResourceSearchRequest, max int) ([]Resource, error) {
	var out []Resource
	seen := map[string]bool{}
	page := req.Page
	for i := 0; i < maxSearchPages; i++ {
		req.Page = page
		resp, err := c.SearchResource(ctx, req)
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Results...)
		if max > 0 && len(out) > max {
			return nil, fmt.Errorf("%w: more than %d", ErrTooManyResults, max)
		}
		if resp.Page == nil || resp.Page.NextToken == "" {
			return out, nil
		}
		if seen[resp.Page.NextToken] {
			return nil, fmt.Errorf("%w: search repeated page token", ErrUnavailable)
		}
		seen[resp.Page.NextToken] = true
		next := PageRequest{Token: resp.Page.NextToken}
		if req.Page != nil {
			next.Limit = req.Page.Limit
		}
		page = &next
	}
	return nil, fmt.Errorf("%w: search exceeded %d pages", ErrUnavailable, maxSearchPages)
}

func (c *Client) post(ctx context.Context, endpoint string, body, out any) error {
	if err := c.do(ctx, http.MethodPost, endpoint, body, out); err != nil {
		// A 404 means the endpoint moved; re-discover on the next call.
		// Timeouts and other failures say nothing about the endpoints.
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			c.invalidate()
		}
		return err
	}
	return nil
}

// do performs one PDP call with the per-call timeout, the PEP token and
// the request ID, and decodes a size-limited JSON body into out.
func (c *Client) do(ctx context.Context, method, endpoint string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("authzen: encode request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrUnavailable, err)
	}
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if id := RequestIDFrom(ctx); id != "" {
		httpReq.Header.Set("X-Request-ID", id)
	}
	if c.tokens != nil {
		tok, err := c.tokens.Token(ctx)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		if tok != "" {
			httpReq.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: %s %s: %w", ErrUnavailable, method, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read response: %w", ErrUnavailable, err)
	}
	if int64(len(raw)) > c.maxBytes {
		return fmt.Errorf("%w: response exceeds %d bytes", ErrUnavailable, c.maxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: %s %s: %w", ErrUnavailable, method, endpoint, &statusError{code: resp.StatusCode})
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: decode response: %w", ErrUnavailable, err)
	}
	return nil
}

// statusError is a non-2xx PDP response.
type statusError struct{ code int }

func (e *statusError) Error() string { return fmt.Sprintf("returned status %d", e.code) }
