package authz

import (
	"context"
	"errors"
	"sync"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

var errPDPDown = errors.New("pdp down")

// mockPDP is a Decider whose decisions come from decide.
type mockPDP struct {
	mu     sync.Mutex
	decide func(authzen.EvaluationRequest) bool
	// respContext, when set, supplies each response's context.
	respContext func(authzen.EvaluationRequest) map[string]any
	err         error // returned by Evaluate / Evaluations / search
	shortBy     int   // drop this many decisions from batch responses
	search      bool
	searchErr   error
	results     []authzen.Resource
	// resultsErr fails SearchResources only.
	resultsErr error

	evals    []authzen.EvaluationRequest
	batches  []authzen.EvaluationsRequest
	searches []authzen.ResourceSearchRequest
	// searchMax is the max passed to the last SearchResources call.
	searchMax int
}

func newMockPDP(decide func(authzen.EvaluationRequest) bool) *mockPDP {
	if decide == nil {
		decide = func(authzen.EvaluationRequest) bool { return true }
	}
	return &mockPDP{decide: decide}
}

func (m *mockPDP) Evaluate(_ context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evals = append(m.evals, req)
	if m.err != nil {
		return authzen.EvaluationResponse{}, m.err
	}
	return authzen.EvaluationResponse{Decision: m.decide(req), Context: m.contextFor(req)}, nil
}

func (m *mockPDP) contextFor(req authzen.EvaluationRequest) map[string]any {
	if m.respContext == nil {
		return nil
	}
	return m.respContext(req)
}

func (m *mockPDP) Evaluations(_ context.Context, req authzen.EvaluationsRequest) (authzen.EvaluationsResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches = append(m.batches, req)
	if m.err != nil {
		return authzen.EvaluationsResponse{}, m.err
	}
	var out []authzen.EvaluationResponse
	for i := range req.Evaluations {
		item, err := req.Expand(i)
		if err != nil {
			return authzen.EvaluationsResponse{}, err
		}
		d := m.decide(item)
		out = append(out, authzen.EvaluationResponse{Decision: d, Context: m.contextFor(item)})
		if req.Semantic() == authzen.DenyOnFirstDeny && !d {
			break
		}
	}
	if m.shortBy > 0 && len(out) >= m.shortBy {
		out = out[:len(out)-m.shortBy]
	}
	return authzen.EvaluationsResponse{Evaluations: out}, nil
}

func (m *mockPDP) SupportsResourceSearch(context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.search, m.searchErr
}

func (m *mockPDP) SearchResources(_ context.Context, req authzen.ResourceSearchRequest, max int) ([]authzen.Resource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.searches = append(m.searches, req)
	m.searchMax = max
	if m.err != nil {
		return nil, m.err
	}
	if m.resultsErr != nil {
		return nil, m.resultsErr
	}
	return m.results, nil
}

func (m *mockPDP) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.evals) + len(m.batches) + len(m.searches)
}

// mockLister returns fixed candidates.
type mockLister struct {
	ids       []ResourceID
	err       error
	lastLimit int
	lastNS    string
}

func (l *mockLister) ListIDs(_ context.Context, _ string, namespace string, limit int) ([]ResourceID, error) {
	l.lastLimit, l.lastNS = limit, namespace
	if l.err != nil {
		return nil, l.err
	}
	if limit > 0 && len(l.ids) > limit {
		return l.ids[:limit], nil
	}
	return l.ids, nil
}

// userSession is an authenticated user principal.
type userSession struct{ p auth.Principal }

func (s userSession) Principal() auth.Principal { return s.p }

func alice() auth.Principal {
	return auth.Principal{
		Subject: "alice-sub", Issuer: "https://idp.example", ClientID: "registry-ui",
		Username: "alice", Roles: []string{"registry-reader"}, Groups: []string{"eng"},
		Claims: map[string]any{"preferred_username": "alice", "azp": "registry-ui"},
	}
}

func userCtx(p auth.Principal) context.Context {
	ctx := auth.AuthSessionTo(context.Background(), userSession{p: p})
	return authzen.WithRequestID(ctx, "req-1")
}
