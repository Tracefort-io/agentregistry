package authzen

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePDP is an httptest AuthZEN PDP whose behavior each test configures.
type fakePDP struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	pdpID         string // policy_decision_point override; "" = server URL
	noBatch       bool
	search        bool
	evalBody      string // raw response for /access/v1/evaluation; "" = decide()
	evalStatus    int
	delay         time.Duration
	decide        func(EvaluationRequest) bool
	searchPages   map[string]ResourceSearchResponse // keyed by request page token
	lastHeaders   http.Header
	lastBatch     EvaluationsRequest
	evalCalls     atomic.Int32
	batchCalls    atomic.Int32
	discoverCalls atomic.Int32
}

func newFakePDP(t *testing.T) *fakePDP {
	f := &fakePDP{t: t, decide: func(EvaluationRequest) bool { return true }}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePDP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.lastHeaders = r.Header.Clone()
	delay := f.delay
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	w.Header().Set("Content-Type", "application/json")
	body, _ := io.ReadAll(r.Body)
	switch r.URL.Path {
	case WellKnownPath:
		f.discoverCalls.Add(1)
		id := f.pdpID
		if id == "" {
			id = f.srv.URL
		}
		meta := Metadata{PolicyDecisionPoint: id, AccessEvaluationEndpoint: f.srv.URL + "/access/v1/evaluation"}
		if !f.noBatch {
			meta.AccessEvaluationsEndpoint = f.srv.URL + "/access/v1/evaluations"
		}
		if f.search {
			meta.SearchResourceEndpoint = "/access/v1/search/resource" // relative: resolved by the client
		}
		_ = json.NewEncoder(w).Encode(meta)
	case "/access/v1/evaluation":
		f.evalCalls.Add(1)
		if f.evalStatus != 0 {
			w.WriteHeader(f.evalStatus)
			return
		}
		if f.evalBody != "" {
			_, _ = io.WriteString(w, f.evalBody)
			return
		}
		var req EvaluationRequest
		require.NoError(f.t, json.Unmarshal(body, &req))
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": f.decide(req)})
	case "/access/v1/evaluations":
		f.batchCalls.Add(1)
		var req EvaluationsRequest
		require.NoError(f.t, json.Unmarshal(body, &req))
		f.mu.Lock()
		f.lastBatch = req
		f.mu.Unlock()
		out := []map[string]any{}
		for i := range req.Evaluations {
			item, err := req.Expand(i)
			require.NoError(f.t, err)
			d := f.decide(item)
			out = append(out, map[string]any{"decision": d})
			if req.Semantic() == DenyOnFirstDeny && !d {
				break
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"evaluations": out})
	case "/access/v1/search/resource":
		var req ResourceSearchRequest
		require.NoError(f.t, json.Unmarshal(body, &req))
		token := ""
		if req.Page != nil {
			token = req.Page.Token
		}
		_ = json.NewEncoder(w).Encode(f.searchPages[token])
	default:
		http.NotFound(w, r)
	}
}

func (f *fakePDP) client(t *testing.T, mutate func(*Config)) *Client {
	cfg := Config{BaseURL: f.srv.URL + "/", Timeout: time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	return c
}

func sampleReq(id string) EvaluationRequest {
	return EvaluationRequest{
		Subject:  Subject{Type: "user", ID: "alice"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "agent", ID: id},
		Context:  Context{"request_id": "r-" + id, "pep": "test"},
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*fakePDP)
		timeout  time.Duration
		want     bool
		wantErr  error
		errMatch string
	}{
		{name: "permit", setup: func(*fakePDP) {}, want: true},
		{name: "deny", setup: func(f *fakePDP) { f.decide = func(EvaluationRequest) bool { return false } }, want: false},
		{name: "timeout", setup: func(f *fakePDP) { f.delay = 200 * time.Millisecond }, timeout: 50 * time.Millisecond, wantErr: ErrUnavailable},
		{name: "5xx", setup: func(f *fakePDP) { f.evalStatus = http.StatusBadGateway }, wantErr: ErrUnavailable, errMatch: "status 502"},
		{name: "string decision", setup: func(f *fakePDP) { f.evalBody = `{"decision":"true"}` }, wantErr: ErrMalformedDecision},
		{name: "numeric decision", setup: func(f *fakePDP) { f.evalBody = `{"decision":1}` }, wantErr: ErrMalformedDecision},
		{name: "missing decision", setup: func(f *fakePDP) { f.evalBody = `{}` }, wantErr: ErrMalformedDecision},
		{name: "null decision", setup: func(f *fakePDP) { f.evalBody = `{"decision":null}` }, wantErr: ErrUnavailable},
		{name: "not json", setup: func(f *fakePDP) { f.evalBody = `<html>` }, wantErr: ErrUnavailable},
		{name: "discovery mismatch", setup: func(f *fakePDP) { f.pdpID = "https://other.example" }, wantErr: ErrDiscovery},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakePDP(t)
			tt.setup(f)
			c := f.client(t, func(cfg *Config) {
				if tt.timeout > 0 {
					cfg.Timeout = tt.timeout
				}
			})
			got, err := c.Evaluate(context.Background(), sampleReq("default/a"))
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.ErrorIs(t, err, ErrUnavailable, "every failure must be ErrUnavailable")
				if tt.errMatch != "" {
					assert.Contains(t, err.Error(), tt.errMatch)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.Decision)
		})
	}
}

func TestEvaluate_HeadersAndToken(t *testing.T) {
	f := newFakePDP(t)
	c := f.client(t, func(cfg *Config) { cfg.TokenSource = StaticToken("pep-secret") })
	ctx := WithRequestID(context.Background(), "req-42")
	_, err := c.Evaluate(ctx, sampleReq("default/a"))
	require.NoError(t, err)
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, "Bearer pep-secret", f.lastHeaders.Get("Authorization"))
	assert.Equal(t, "application/json", f.lastHeaders.Get("Content-Type"))
	assert.Equal(t, "req-42", f.lastHeaders.Get("X-Request-ID"))
}

func TestEvaluate_NoTokenWithoutSource(t *testing.T) {
	f := newFakePDP(t)
	c := f.client(t, nil)
	_, err := c.Evaluate(context.Background(), sampleReq("default/a"))
	require.NoError(t, err)
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Empty(t, f.lastHeaders.Get("Authorization"))
}

func TestClientCredentialsTokenSource(t *testing.T) {
	var tokenCalls atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"cc-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer idp.Close()
	ts, err := NewClientCredentialsTokenSource(ClientCredentialsConfig{
		TokenURL: idp.URL, ClientID: "pep", ClientSecret: "s", Scopes: []string{"authzen"},
	})
	require.NoError(t, err)

	f := newFakePDP(t)
	c := f.client(t, func(cfg *Config) { cfg.TokenSource = ts })
	for i := 0; i < 3; i++ {
		_, err = c.Evaluate(context.Background(), sampleReq("default/a"))
		require.NoError(t, err)
	}
	f.mu.Lock()
	assert.Equal(t, "Bearer cc-token", f.lastHeaders.Get("Authorization"))
	f.mu.Unlock()
	assert.Equal(t, int32(1), tokenCalls.Load(), "token must be reused until expiry")

	_, err = NewClientCredentialsTokenSource(ClientCredentialsConfig{})
	assert.Error(t, err)
}

func TestEvaluate_PermitCache(t *testing.T) {
	now := time.Unix(1000, 0)
	var nowMu sync.Mutex
	clock := func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	advance := func(d time.Duration) { nowMu.Lock(); now = now.Add(d); nowMu.Unlock() }

	f := newFakePDP(t)
	f.decide = func(r EvaluationRequest) bool { return r.Resource.ID != "default/denied" }
	c := f.client(t, func(cfg *Config) { cfg.CacheTTL = 5 * time.Second; cfg.Now = clock })
	ctx := context.Background()

	// Permit is cached; a different request_id still hits the cache.
	for i := 0; i < 3; i++ {
		req := sampleReq("default/a")
		req.Context["request_id"] = string(rune('a' + i))
		got, err := c.Evaluate(ctx, req)
		require.NoError(t, err)
		require.True(t, got.Decision)
	}
	assert.Equal(t, int32(1), f.evalCalls.Load())

	// Other relevant context is part of the key.
	req := sampleReq("default/a")
	req.Context["pep"] = "other"
	_, err := c.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, int32(2), f.evalCalls.Load())

	// Denials are never cached.
	for i := 0; i < 2; i++ {
		got, err := c.Evaluate(ctx, sampleReq("default/denied"))
		require.NoError(t, err)
		require.False(t, got.Decision)
	}
	assert.Equal(t, int32(4), f.evalCalls.Load())

	// Expiry.
	advance(6 * time.Second)
	_, err = c.Evaluate(ctx, sampleReq("default/a"))
	require.NoError(t, err)
	assert.Equal(t, int32(5), f.evalCalls.Load())
}

func TestEvaluate_ErrorsNotCached(t *testing.T) {
	f := newFakePDP(t)
	f.evalStatus = http.StatusInternalServerError
	c := f.client(t, func(cfg *Config) { cfg.CacheTTL = time.Minute })
	_, err := c.Evaluate(context.Background(), sampleReq("default/a"))
	require.Error(t, err)
	f.evalStatus = 0
	got, err := c.Evaluate(context.Background(), sampleReq("default/a"))
	require.NoError(t, err)
	assert.True(t, got.Decision)
	// A 5xx says nothing about the endpoints, so they are kept.
	assert.Equal(t, int32(1), f.discoverCalls.Load())
}

func TestEvaluate_NotFoundRediscovers(t *testing.T) {
	f := newFakePDP(t)
	f.evalStatus = http.StatusNotFound
	c := f.client(t, nil)
	_, err := c.Evaluate(context.Background(), sampleReq("default/a"))
	require.ErrorIs(t, err, ErrUnavailable)
	f.evalStatus = 0
	_, err = c.Evaluate(context.Background(), sampleReq("default/a"))
	require.NoError(t, err)
	// A 404 means the endpoint moved, so the PDP was re-discovered.
	assert.Equal(t, int32(2), f.discoverCalls.Load())
}

// While discovery is slow, concurrent callers share one discovery call and
// each gives up when its own context ends, instead of queueing behind a lock.
func TestMetadata_ConcurrentCallersShareDiscovery(t *testing.T) {
	f := newFakePDP(t)
	f.delay = 400 * time.Millisecond
	c := f.client(t, func(cfg *Config) { cfg.Timeout = 2 * time.Second })

	const callers = 20
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := c.Evaluate(ctx, sampleReq("default/a"))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	assert.Less(t, time.Since(start), 300*time.Millisecond, "callers must not wait for each other")
	for err := range errs {
		require.ErrorIs(t, err, ErrUnavailable)
	}
	assert.Eventually(t, func() bool { return f.discoverCalls.Load() == 1 }, time.Second, 10*time.Millisecond)
	time.Sleep(f.delay) // let the shared discovery finish
	assert.Equal(t, int32(1), f.discoverCalls.Load(), "one discovery for all callers")
}

func TestMetadata_CachedAndRetriedAfterFailure(t *testing.T) {
	f := newFakePDP(t)
	f.pdpID = "https://wrong.example"
	now := time.Now()
	c := f.client(t, func(cfg *Config) { cfg.Now = func() time.Time { return now } })
	_, err := c.Metadata(context.Background())
	require.ErrorIs(t, err, ErrDiscovery)
	f.pdpID = ""
	// A failed discovery is remembered briefly, so a down PDP is not
	// called again by every request.
	_, err = c.Metadata(context.Background())
	require.ErrorIs(t, err, ErrDiscovery)
	assert.Equal(t, int32(1), f.discoverCalls.Load())
	now = now.Add(discoveryRetryAfter)
	meta, err := c.Metadata(context.Background())
	require.NoError(t, err)
	_, err = c.Metadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(2), f.discoverCalls.Load())
	assert.Equal(t, f.srv.URL+"/access/v1/evaluations", meta.AccessEvaluationsEndpoint)
}

func TestSupportsResourceSearch(t *testing.T) {
	for _, search := range []bool{true, false} {
		f := newFakePDP(t)
		f.search = search
		got, err := f.client(t, nil).SupportsResourceSearch(context.Background())
		require.NoError(t, err)
		assert.Equal(t, search, got)
	}
}

func TestEvaluations(t *testing.T) {
	subject := &Subject{Type: "user", ID: "alice"}
	batch := func(sem EvaluationsSemantic, ids ...string) EvaluationsRequest {
		req := EvaluationsRequest{Subject: subject, Action: &Action{Name: "read"}, Options: &EvaluationsOptions{EvaluationsSemantic: sem}}
		for _, id := range ids {
			req.Evaluations = append(req.Evaluations, EvaluationItem{Resource: &Resource{Type: "agent", ID: id}})
		}
		return req
	}
	tests := []struct {
		name    string
		noBatch bool
		req     EvaluationsRequest
		want    []bool
	}{
		{name: "execute_all", req: batch(ExecuteAll, "ns/a", "ns/deny", "ns/b"), want: []bool{true, false, true}},
		{name: "deny_on_first_deny stops", req: batch(DenyOnFirstDeny, "ns/a", "ns/deny", "ns/b"), want: []bool{true, false}},
		{name: "deny_on_first_deny all permit", req: batch(DenyOnFirstDeny, "ns/a", "ns/b"), want: []bool{true, true}},
		{name: "fallback execute_all", noBatch: true, req: batch(ExecuteAll, "ns/a", "ns/deny", "ns/b"), want: []bool{true, false, true}},
		{name: "fallback deny_on_first_deny", noBatch: true, req: batch(DenyOnFirstDeny, "ns/a", "ns/deny", "ns/b"), want: []bool{true, false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakePDP(t)
			f.noBatch = tt.noBatch
			f.decide = func(r EvaluationRequest) bool { return !strings.HasSuffix(r.Resource.ID, "deny") }
			got, err := f.client(t, nil).Evaluations(context.Background(), tt.req)
			require.NoError(t, err)
			var decisions []bool
			for _, d := range got.Evaluations {
				decisions = append(decisions, d.Decision)
			}
			assert.Equal(t, tt.want, decisions)
			if !tt.noBatch {
				f.mu.Lock()
				assert.Equal(t, tt.req.Semantic(), f.lastBatch.Semantic(), "semantic must be passed through")
				f.mu.Unlock()
			}
		})
	}
}

func TestEvaluations_CacheAndShape(t *testing.T) {
	f := newFakePDP(t)
	c := f.client(t, func(cfg *Config) { cfg.CacheTTL = time.Minute })
	req := EvaluationsRequest{
		Subject: &Subject{Type: "user", ID: "alice"}, Action: &Action{Name: "read"},
		Evaluations: []EvaluationItem{{Resource: &Resource{Type: "agent", ID: "ns/a"}}, {Resource: &Resource{Type: "agent", ID: "ns/b"}}},
	}
	_, err := c.Evaluations(context.Background(), req)
	require.NoError(t, err)
	_, err = c.Evaluations(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, int32(1), f.batchCalls.Load(), "all-permit batch must be served from cache")

	// Single evaluation of a batch item is a cache hit too.
	_, err = c.Evaluate(context.Background(), EvaluationRequest{Subject: *req.Subject, Action: *req.Action, Resource: *req.Evaluations[0].Resource})
	require.NoError(t, err)
	assert.Equal(t, int32(0), f.evalCalls.Load())

	_, err = c.Evaluations(context.Background(), EvaluationsRequest{Evaluations: []EvaluationItem{{}}})
	assert.Error(t, err, "item without subject must fail")
}

func TestCheckBatchShape(t *testing.T) {
	d := func(bs ...bool) []EvaluationResponse {
		out := make([]EvaluationResponse, len(bs))
		for i, b := range bs {
			out[i].Decision = b
		}
		return out
	}
	tests := []struct {
		name    string
		sem     EvaluationsSemantic
		n       int
		got     []EvaluationResponse
		wantErr bool
	}{
		{"execute_all full", ExecuteAll, 2, d(true, false), false},
		{"execute_all short", ExecuteAll, 2, d(true), true},
		{"empty", ExecuteAll, 1, nil, true},
		{"too long", ExecuteAll, 1, d(true, true), true},
		{"deny short on deny", DenyOnFirstDeny, 3, d(true, false), false},
		{"deny short on permit", DenyOnFirstDeny, 3, d(true, true), true},
		{"permit short on permit", PermitOnFirstPermit, 3, d(false, true), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkBatchShape(tt.sem, tt.n, tt.got)
			assert.Equal(t, tt.wantErr, err != nil, "err = %v", err)
		})
	}
}

func TestSearchResources(t *testing.T) {
	f := newFakePDP(t)
	f.search = true
	f.searchPages = map[string]ResourceSearchResponse{
		"":   {Results: []Resource{{Type: "agent", ID: "ns/a"}}, Page: &PageResponse{NextToken: "p2"}},
		"p2": {Results: []Resource{{Type: "agent", ID: "ns/b"}, {Type: "agent", ID: "ns/c"}}, Page: &PageResponse{NextToken: "p3"}},
		"p3": {Results: []Resource{{Type: "agent", ID: "ns/d"}}},
	}
	c := f.client(t, nil)
	req := ResourceSearchRequest{Subject: Subject{Type: "user", ID: "alice"}, Action: Action{Name: "read"}, Resource: Resource{Type: "agent"}}

	got, err := c.SearchResources(context.Background(), req, 0)
	require.NoError(t, err)
	var ids []string
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	assert.Equal(t, []string{"ns/a", "ns/b", "ns/c", "ns/d"}, ids)

	_, err = c.SearchResources(context.Background(), req, 2)
	assert.ErrorIs(t, err, ErrTooManyResults)

	// A PDP that loops on the same token is an error, not an infinite loop.
	f.searchPages["p3"] = ResourceSearchResponse{Page: &PageResponse{NextToken: "p2"}}
	_, err = c.SearchResources(context.Background(), req, 0)
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestSearchResource_NotSupported(t *testing.T) {
	f := newFakePDP(t)
	_, err := f.client(t, nil).SearchResource(context.Background(), ResourceSearchRequest{})
	assert.True(t, errors.Is(err, ErrSearchNotSupported))
}

func TestResponseSizeLimit(t *testing.T) {
	f := newFakePDP(t)
	f.evalBody = `{"decision":true,"context":{"pad":"` + strings.Repeat("x", 2048) + `"}}`
	c := f.client(t, func(cfg *Config) { cfg.MaxResponseBytes = 1024 })
	_, err := c.Evaluate(context.Background(), sampleReq("default/a"))
	require.ErrorIs(t, err, ErrUnavailable)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestNew_InvalidBaseURL(t *testing.T) {
	for _, u := range []string{"", "not a url", "ftp://pdp.example", "/relative"} {
		_, err := New(Config{BaseURL: u})
		assert.Error(t, err, u)
	}
}

// Within one request, identical decisions are asked once, denials included,
// whatever the cache TTL. Without a memo every call reaches the PDP.
func TestEvaluate_DecisionMemo(t *testing.T) {
	f := newFakePDP(t)
	f.decide = func(r EvaluationRequest) bool { return r.Resource.ID != "default/denied" }
	c := f.client(t, nil) // CacheTTL 0: no permit cache

	ctx := WithDecisionMemo(WithRequestID(context.Background(), "req-1"))
	for range 3 {
		got, err := c.Evaluate(ctx, sampleReq("default/a"))
		require.NoError(t, err)
		assert.True(t, got.Decision)
		got, err = c.Evaluate(ctx, sampleReq("default/denied"))
		require.NoError(t, err)
		assert.False(t, got.Decision)
	}
	assert.Equal(t, int32(2), f.evalCalls.Load(), "one call per distinct request")

	// A new request gets a new memo.
	_, err := c.Evaluate(WithDecisionMemo(context.Background()), sampleReq("default/a"))
	require.NoError(t, err)
	assert.Equal(t, int32(3), f.evalCalls.Load())

	// Without a memo, nothing is remembered.
	for range 2 {
		_, err := c.Evaluate(context.Background(), sampleReq("default/a"))
		require.NoError(t, err)
	}
	assert.Equal(t, int32(5), f.evalCalls.Load())
}

func TestEvaluate_DecisionMemoSkipsErrors(t *testing.T) {
	f := newFakePDP(t)
	f.evalStatus = http.StatusInternalServerError
	c := f.client(t, nil)
	ctx := WithDecisionMemo(context.Background())

	_, err := c.Evaluate(ctx, sampleReq("default/a"))
	require.Error(t, err)
	f.evalStatus = 0
	got, err := c.Evaluate(ctx, sampleReq("default/a"))
	require.NoError(t, err, "a failure is not remembered")
	assert.True(t, got.Decision)
}
