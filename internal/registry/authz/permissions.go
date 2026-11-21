package authz

import (
	"context"
	"fmt"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// Permissions asks the PDP, in execute_all batches, which actions the caller
// may take on each covered kind in namespace ("" for every namespace), which
// they may ask approval for (a requestable denial), and whether the caller is
// a registry admin. Each kind is asked about as its collection, id
// "<namespace>/*" (or "*"), the resource lists use. A SystemSession may do
// everything; no session is a 401 and a PDP failure a 503.
func (p *PEP) Permissions(ctx context.Context, namespace string) (types.Permissions, error) {
	c, err := p.callerFrom(ctx)
	if err != nil {
		return types.Permissions{}, err
	}
	if c.system {
		return types.AllPermissions(p.kinds), nil
	}

	type check struct {
		kind   string // "" for the admin check
		action string
		res    authzen.Resource
	}
	checks := []check{{action: ActionAdmin, res: registryResource}}
	for _, kind := range p.kinds {
		res := listResource(kind, namespace)
		for _, action := range types.KindActions(kind) {
			checks = append(checks, check{kind: kind, action: action, res: res})
		}
	}

	out := types.Permissions{
		Kinds:       make(map[string][]string, len(p.kinds)),
		Requestable: make(map[string][]string, len(p.kinds)),
	}
	for _, kind := range p.kinds {
		out.Kinds[kind] = []string{}
		out.Requestable[kind] = []string{}
	}
	reqCtx := requestContext(ctx)
	for start := 0; start < len(checks); start += evaluationsChunk {
		chunk := checks[start:min(start+evaluationsChunk, len(checks))]
		req := authzen.EvaluationsRequest{
			Subject:     &c.subject,
			Context:     reqCtx,
			Options:     &authzen.EvaluationsOptions{EvaluationsSemantic: authzen.ExecuteAll},
			Evaluations: make([]authzen.EvaluationItem, len(chunk)),
		}
		for i := range chunk {
			req.Evaluations[i] = authzen.EvaluationItem{
				Action:   &authzen.Action{Name: chunk[i].action},
				Resource: &chunk[i].res,
			}
		}
		resp, err := p.client.Evaluations(ctx, req)
		if err == nil && len(resp.Evaluations) != len(chunk) {
			err = fmt.Errorf("batch of %d returned %d decisions", len(chunk), len(resp.Evaluations))
		}
		if err != nil {
			p.logError(ctx, c.subject, "permissions", authzen.Resource{Type: "registry", ID: namespace}, err)
			return types.Permissions{}, unavailable(err)
		}
		for i, d := range resp.Evaluations {
			kind, action := chunk[i].kind, chunk[i].action
			switch {
			case d.Decision && kind == "":
				out.Admin = true
			case d.Decision:
				out.Kinds[kind] = append(out.Kinds[kind], action)
			case kind != "" && bindingToken(d.Context) != "":
				out.Requestable[kind] = append(out.Requestable[kind], action)
			}
		}
	}
	return out, nil
}
