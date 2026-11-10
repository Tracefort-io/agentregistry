package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

const wantPredicate = "(namespace, name) IN (SELECT * FROM unnest($1::text[], $2::text[]))"

func listIn(namespace string) types.AuthorizeInput {
	return types.AuthorizeInput{Verb: "list", Kind: v1alpha1.KindAgent, Namespace: namespace}
}

func TestListFilter_Search(t *testing.T) {
	pdp := newMockPDP(nil)
	pdp.search = true
	pdp.results = []authzen.Resource{
		{Type: "agent", ID: "team/b"},
		{Type: "agent", ID: "team/a"},
		{Type: "agent", ID: "other/c"},
		{Type: "skill", ID: "team/not-an-agent"},
		{Type: "agent", ID: "no-slash"},
		{Type: "agent", ID: "team/a"}, // duplicate
		{ID: "team/name/with/slash"},
	}
	p := newPEP(t, pdp, func(c *Config) { c.Lister = &mockLister{err: errors.New("must not be called")} })

	where, args, err := p.ListFilter(userCtx(alice()), listIn(""))
	require.NoError(t, err)
	assert.Equal(t, wantPredicate, where)
	assert.Equal(t, []any{
		[]string{"other", "team", "team", "team"},
		[]string{"c", "a", "b", "name/with/slash"},
	}, args)

	require.Len(t, pdp.evals, 1)
	assert.Equal(t, "list", pdp.evals[0].Action.Name)
	assert.Equal(t, "*", pdp.evals[0].Resource.ID)
	require.Len(t, pdp.searches, 1)
	s := pdp.searches[0]
	assert.Equal(t, "read", s.Action.Name)
	assert.Equal(t, authzen.Resource{Type: "agent"}, s.Resource)
	assert.Equal(t, "alice-sub", s.Subject.ID)

	// Namespace-scoped lists keep only that namespace.
	where, args, err = p.ListFilter(userCtx(alice()), listIn("other"))
	require.NoError(t, err)
	assert.Equal(t, wantPredicate, where)
	assert.Equal(t, []any{[]string{"other"}, []string{"c"}}, args)
	assert.Equal(t, "other/*", pdp.evals[1].Resource.ID)
}

// Resource Search results are capped like list candidates, so a PDP cannot
// push an unbounded id set into memory and the SQL predicate.
func TestListFilter_SearchIsCapped(t *testing.T) {
	for _, tt := range []struct {
		name               string
		listMax, searchMax int
		want               int
	}{
		{"defaults to the list cap", 250, 0, 250},
		{"default list cap", 0, 0, defaultListMax},
		{"explicit search cap", 250, 40, 40},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(nil)
			pdp.search = true
			p := newPEP(t, pdp, func(c *Config) { c.ListMax, c.SearchMax = tt.listMax, tt.searchMax })
			_, _, err := p.ListFilter(userCtx(alice()), listIn(""))
			require.NoError(t, err)
			assert.Equal(t, tt.want, pdp.searchMax)
		})
	}

	// Too many results is a 503, like too many candidates.
	pdp := newMockPDP(nil)
	pdp.search = true
	pdp.resultsErr = authzen.ErrTooManyResults
	p := newPEP(t, pdp, nil)
	_, _, err := p.ListFilter(userCtx(alice()), listIn(""))
	assert.Equal(t, 503, StatusOf(err))
}

func TestListFilter_Evaluations(t *testing.T) {
	var candidates []ResourceID
	for i := 0; i < 250; i++ {
		candidates = append(candidates, ResourceID{Namespace: "team", Name: fmt.Sprintf("a%03d", i)})
	}
	pdp := newMockPDP(func(r authzen.EvaluationRequest) bool {
		// list is permitted; read only on even rows.
		if r.Action.Name == "list" {
			return true
		}
		var n int
		_, _ = fmt.Sscanf(r.Resource.ID, "team/a%03d", &n)
		return n%2 == 0
	})
	lister := &mockLister{ids: candidates}
	p := newPEP(t, pdp, func(c *Config) { c.Lister = lister; c.ListMax = 300 })

	where, args, err := p.ListFilter(userCtx(alice()), listIn("team"))
	require.NoError(t, err)
	assert.Equal(t, wantPredicate, where)
	require.Len(t, args, 2)
	assert.Len(t, args[0], 125)
	assert.Equal(t, "a000", args[1].([]string)[0])
	assert.Equal(t, "a002", args[1].([]string)[1])

	assert.Equal(t, 301, lister.lastLimit, "lister asked for one more than the cap")
	assert.Equal(t, "team", lister.lastNS)
	require.Len(t, pdp.batches, 3, "250 candidates in chunks of 100")
	for _, b := range pdp.batches {
		assert.Equal(t, authzen.ExecuteAll, b.Semantic())
		assert.Equal(t, "read", b.Action.Name)
		assert.Equal(t, "agent", b.Evaluations[0].Resource.Type)
	}
	assert.Empty(t, pdp.searches)
}

// concurrentPDP records how many evaluations batches run at once.
type concurrentPDP struct {
	*mockPDP
	inFlight, peak atomic.Int32
}

func (c *concurrentPDP) Evaluations(ctx context.Context, req authzen.EvaluationsRequest) (authzen.EvaluationsResponse, error) {
	n := c.inFlight.Add(1)
	for {
		peak := c.peak.Load()
		if n <= peak || c.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	c.inFlight.Add(-1)
	return c.mockPDP.Evaluations(ctx, req)
}

// Candidate batches run in parallel, a few at a time, and the permitted rows
// keep the candidates' order.
func TestListFilter_EvaluationsRunInParallel(t *testing.T) {
	candidates := make([]ResourceID, 0, 1000)
	for i := range 1000 {
		candidates = append(candidates, ResourceID{"team", fmt.Sprintf("a%04d", i)})
	}
	pdp := &concurrentPDP{mockPDP: newMockPDP(nil)}
	p, err := New(Config{Client: pdp, Lister: &mockLister{ids: candidates}, ListMax: 1000})
	require.NoError(t, err)

	_, args, err := p.ListFilter(userCtx(alice()), listIn("team"))
	require.NoError(t, err)

	assert.Len(t, pdp.batches, 10)
	assert.Greater(t, pdp.peak.Load(), int32(1), "batches must overlap")
	assert.LessOrEqual(t, pdp.peak.Load(), int32(maxParallelBatches))
	names := args[1].([]string)
	require.Len(t, names, 1000)
	assert.True(t, sort.StringsAreSorted(names))
}

func TestListFilter_Errors(t *testing.T) {
	deny := func(authzen.EvaluationRequest) bool { return false }
	denyRead := func(r authzen.EvaluationRequest) bool { return r.Action.Name == "list" }
	three := []ResourceID{{"n", "a"}, {"n", "b"}, {"n", "c"}}
	tests := []struct {
		name       string
		ctx        context.Context
		decide     func(authzen.EvaluationRequest) bool
		search     bool
		searchErr  error
		pdpErr     error
		shortBy    int
		lister     CandidateLister
		listMax    int
		wantStatus int
		wantWhere  string
		wantIs     error
	}{
		{name: "list denied", ctx: userCtx(alice()), decide: deny, lister: &mockLister{}, wantStatus: 403, wantIs: auth.ErrForbidden},
		{name: "cap exceeded", ctx: userCtx(alice()), lister: &mockLister{ids: three}, listMax: 2, wantStatus: 503, wantIs: auth.ErrForbidden},
		{name: "cap exactly reached", ctx: userCtx(alice()), lister: &mockLister{ids: three}, listMax: 3, wantWhere: wantPredicate},
		{name: "nothing readable", ctx: userCtx(alice()), decide: denyRead, lister: &mockLister{ids: three}, wantWhere: "false"},
		{name: "no candidates", ctx: userCtx(alice()), lister: &mockLister{}, wantWhere: "false"},
		{name: "search returns nothing", ctx: userCtx(alice()), search: true, wantWhere: "false"},
		{name: "no lister without search", ctx: userCtx(alice()), wantStatus: 503, wantIs: auth.ErrForbidden},
		{name: "discovery failure", ctx: userCtx(alice()), searchErr: errPDPDown, wantStatus: 503, wantIs: errPDPDown},
		{name: "pdp failure", ctx: userCtx(alice()), pdpErr: errPDPDown, lister: &mockLister{ids: three}, wantStatus: 503, wantIs: auth.ErrForbidden},
		{name: "short batch", ctx: userCtx(alice()), shortBy: 1, lister: &mockLister{ids: three}, wantStatus: 503},
		{name: "lister failure is internal", ctx: userCtx(alice()), lister: &mockLister{err: errors.New("db down")}, wantStatus: 0, wantIs: nil},
		{name: "unauthenticated", ctx: context.Background(), lister: &mockLister{}, wantStatus: 401, wantIs: auth.ErrUnauthenticated},
		{name: "system session has no filter", ctx: auth.WithSystemContext(context.Background()), decide: deny, wantWhere: ""},
		{name: "public session filtered", ctx: auth.WithPublicContext(context.Background()), decide: denyRead, lister: &mockLister{ids: three}, wantWhere: "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(tt.decide)
			pdp.search, pdp.searchErr, pdp.shortBy = tt.search, tt.searchErr, tt.shortBy
			p := newPEP(t, pdp, func(c *Config) { c.Lister = tt.lister; c.ListMax = tt.listMax })
			pdp.err = tt.pdpErr
			if tt.pdpErr != nil {
				// Let the list check pass; fail the per-row batch.
				pdp.err = nil
				p.client = &failBatches{mockPDP: pdp, err: tt.pdpErr}
			}
			where, args, err := p.ListFilter(tt.ctx, listIn("n"))
			if tt.name == "lister failure is internal" {
				require.Error(t, err)
				assert.Zero(t, StatusOf(err))
				return
			}
			if tt.wantStatus != 0 {
				require.Error(t, err)
				assert.Equal(t, tt.wantStatus, StatusOf(err))
				if tt.wantIs != nil {
					assert.ErrorIs(t, err, tt.wantIs)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantWhere, where)
			if where == "false" || where == "" {
				assert.Nil(t, args)
			}
		})
	}
}

// failBatches fails evaluations and search but not single evaluations.
type failBatches struct {
	*mockPDP
	err error
}

func (f *failBatches) Evaluations(context.Context, authzen.EvaluationsRequest) (authzen.EvaluationsResponse, error) {
	return authzen.EvaluationsResponse{}, f.err
}

func TestPredicate(t *testing.T) {
	tests := []struct {
		name      string
		ids       []ResourceID
		wantWhere string
		wantArgs  []any
	}{
		{name: "empty matches nothing", wantWhere: "false"},
		{name: "single", ids: []ResourceID{{"ns", "a"}}, wantWhere: wantPredicate, wantArgs: []any{[]string{"ns"}, []string{"a"}}},
		{
			name:      "sorted and deduplicated",
			ids:       []ResourceID{{"b", "x"}, {"a", "y"}, {"b", "x"}, {"a", "a"}},
			wantWhere: wantPredicate,
			wantArgs:  []any{[]string{"a", "a", "b"}, []string{"a", "y", "x"}},
		},
		{
			name:      "hostile values stay in args",
			ids:       []ResourceID{{"ns", "x'); DROP TABLE agents; --"}},
			wantWhere: wantPredicate,
			wantArgs:  []any{[]string{"ns"}, []string{"x'); DROP TABLE agents; --"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			where, args := Predicate(tt.ids)
			assert.Equal(t, tt.wantWhere, where)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}
