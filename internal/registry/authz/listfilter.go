package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

const (
	// evaluationsChunk bounds one evaluations batch of list candidates.
	evaluationsChunk = 100
	// maxParallelBatches bounds the batches of one list in flight at once.
	maxParallelBatches = 4
)

// ResourceID identifies one row by its store key.
type ResourceID struct {
	Namespace string
	Name      string
}

// CandidateLister returns the distinct (namespace, name) keys of a kind,
// all namespaces when namespace is "". It returns at most limit keys; a
// result of exactly limit means there may be more.
type CandidateLister interface {
	ListIDs(ctx context.Context, kind, namespace string, limit int) ([]ResourceID, error)
}

// ListFilters returns one list filter per covered kind.
func (p *PEP) ListFilters() map[string]types.ListFilter {
	out := make(map[string]types.ListFilter, len(p.kinds))
	for _, kind := range p.kinds {
		out[kind] = p.ListFilter
	}
	return out
}

// ListFilter authorizes `list` on the kind, collects the rows the caller
// may `read` (Resource Search when the PDP advertises it, else evaluations
// over at most ListMax candidates) and returns them as a parameterized
// predicate. SystemSession gets no filter.
func (p *PEP) ListFilter(ctx context.Context, in types.AuthorizeInput) (string, []any, error) {
	c, err := p.callerFrom(ctx)
	if err != nil {
		return "", nil, err
	}
	if c.system {
		return "", nil, nil
	}
	res := listResource(in.Kind, in.Namespace)
	permit, err := p.evaluate(ctx, c.subject, ActionList, res)
	if err != nil {
		return "", nil, err
	}
	if !permit {
		return "", nil, forbidden(fmt.Sprintf("not permitted to %s %s %s", ActionList, res.Type, res.ID))
	}

	search, err := p.client.SupportsResourceSearch(ctx)
	if err != nil {
		p.logError(ctx, c.subject, ActionRead, res, err)
		return "", nil, unavailable(err)
	}
	var ids []ResourceID
	if search {
		ids, err = p.searchReadable(ctx, c.subject, in.Kind, in.Namespace)
	} else {
		ids, err = p.evaluateReadable(ctx, c.subject, in.Kind, in.Namespace)
	}
	if err != nil {
		return "", nil, err
	}
	where, args := Predicate(ids)
	return where, args, nil
}

// searchReadable asks the PDP which resources of the kind the subject may read.
func (p *PEP) searchReadable(ctx context.Context, subject authzen.Subject, kind, namespace string) ([]ResourceID, error) {
	typ := resourceType(kind)
	results, err := p.client.SearchResources(ctx, authzen.ResourceSearchRequest{
		Subject:  subject,
		Action:   authzen.Action{Name: ActionRead},
		Resource: authzen.Resource{Type: typ},
		Context:  requestContext(ctx),
	}, p.searchMax)
	if err != nil {
		p.logError(ctx, subject, ActionRead, authzen.Resource{Type: typ}, err)
		return nil, unavailable(err)
	}
	ids := make([]ResourceID, 0, len(results))
	for _, r := range results {
		if r.Type != "" && r.Type != typ {
			continue
		}
		ns, name, ok := strings.Cut(r.ID, "/")
		if !ok || ns == "" || name == "" {
			p.log.DebugContext(ctx, "authz ignoring unparseable search result", "resource_type", r.Type, "resource_id", r.ID)
			continue
		}
		if namespace != "" && ns != namespace {
			continue
		}
		ids = append(ids, ResourceID{Namespace: ns, Name: name})
	}
	p.log.DebugContext(ctx, "authz list via search", "subject_id", subject.ID, "resource_type", typ,
		"permitted", len(ids), "request_id", authzen.RequestIDFrom(ctx))
	return ids, nil
}

// evaluateReadable checks read on each candidate row with execute_all batches.
func (p *PEP) evaluateReadable(ctx context.Context, subject authzen.Subject, kind, namespace string) ([]ResourceID, error) {
	typ := resourceType(kind)
	if p.lister == nil {
		err := errors.New("pdp has no resource search and no candidate lister is configured")
		p.logError(ctx, subject, ActionRead, authzen.Resource{Type: typ}, err)
		return nil, unavailable(err)
	}
	candidates, err := p.lister.ListIDs(ctx, kind, namespace, p.listMax+1)
	if err != nil {
		return nil, fmt.Errorf("list %s candidates: %w", kind, err)
	}
	if len(candidates) > p.listMax {
		err := fmt.Errorf("more than %d %s rows to authorize; enable resource search on the pdp", p.listMax, typ)
		p.logError(ctx, subject, ActionRead, authzen.Resource{Type: typ}, err)
		return nil, unavailable(err)
	}

	// Batches run in parallel, a few at a time; each fills its own slot so
	// the permitted rows keep the candidates' order.
	chunks := (len(candidates) + evaluationsChunk - 1) / evaluationsChunk
	results := make([][]ResourceID, chunks)
	reqCtx := requestContext(ctx)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxParallelBatches)
	for i := range chunks {
		chunk := candidates[i*evaluationsChunk : min((i+1)*evaluationsChunk, len(candidates))]
		g.Go(func() error {
			permitted, err := p.readableChunk(gctx, subject, kind, chunk, reqCtx)
			results[i] = permitted
			return err
		})
	}
	if err := g.Wait(); err != nil {
		p.logError(ctx, subject, ActionRead, authzen.Resource{Type: typ}, err)
		return nil, unavailable(err)
	}
	permitted := make([]ResourceID, 0, len(candidates))
	for _, r := range results {
		permitted = append(permitted, r...)
	}
	p.log.DebugContext(ctx, "authz list via evaluations", "subject_id", subject.ID, "resource_type", typ,
		"candidates", len(candidates), "permitted", len(permitted), "request_id", authzen.RequestIDFrom(ctx))
	return permitted, nil
}

// readableChunk checks read on one batch of candidates with execute_all.
func (p *PEP) readableChunk(ctx context.Context, subject authzen.Subject, kind string, chunk []ResourceID, reqCtx authzen.Context) ([]ResourceID, error) {
	req := authzen.EvaluationsRequest{
		Subject:     &subject,
		Action:      &authzen.Action{Name: ActionRead},
		Context:     reqCtx,
		Options:     &authzen.EvaluationsOptions{EvaluationsSemantic: authzen.ExecuteAll},
		Evaluations: make([]authzen.EvaluationItem, len(chunk)),
	}
	for i, id := range chunk {
		res := objectResource(kind, id.Namespace, id.Name, "")
		req.Evaluations[i] = authzen.EvaluationItem{Resource: &res}
	}
	resp, err := p.client.Evaluations(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.Evaluations) != len(chunk) {
		return nil, fmt.Errorf("batch of %d returned %d decisions", len(chunk), len(resp.Evaluations))
	}
	var permitted []ResourceID
	for i, d := range resp.Evaluations {
		if d.Decision {
			permitted = append(permitted, chunk[i])
		}
	}
	return permitted, nil
}

// Predicate renders the permitted keys as a v1alpha1store.ListOpts
// ExtraWhere fragment with placeholders $1 (namespaces) and $2 (names).
// The columns exist on both tagged and mutable stores; for tagged kinds
// every tag of a permitted name matches. An empty set matches nothing.
func Predicate(ids []ResourceID) (string, []any) {
	if len(ids) == 0 {
		return "false", nil
	}
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b ResourceID) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	sorted = slices.Compact(sorted)
	namespaces := make([]string, len(sorted))
	names := make([]string, len(sorted))
	for i, id := range sorted {
		namespaces[i] = id.Namespace
		names[i] = id.Name
	}
	return "(namespace, name) IN (SELECT * FROM unnest($1::text[], $2::text[]))", []any{namespaces, names}
}
