package authz

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

type auditCollector struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *auditCollector) Record(_ context.Context, e audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func TestPEP_AuditsRefusedReadsAndLists(t *testing.T) {
	deny := func(authzen.EvaluationRequest) bool { return false }
	tests := []struct {
		name        string
		ctx         context.Context
		verb        string
		decide      func(authzen.EvaluationRequest) bool
		pdpErr      error
		viaList     bool
		wantAction  string
		wantContain string
	}{
		{name: "permitted read", ctx: userCtx(alice()), verb: "get"},
		{name: "refused read", ctx: userCtx(alice()), verb: "get", decide: deny, wantAction: audit.ActionRead, wantContain: "not found"},
		{name: "refused list", ctx: userCtx(alice()), verb: "list", decide: deny, wantAction: audit.ActionList, wantContain: "not permitted"},
		{name: "refused list filter", ctx: userCtx(alice()), viaList: true, decide: deny, wantAction: audit.ActionList, wantContain: "not permitted"},
		{name: "read with the PDP down", ctx: userCtx(alice()), verb: "get", pdpErr: errPDPDown, wantAction: audit.ActionRead, wantContain: "unavailable"},
		// The resource pipeline records applies and deletes with their outcome.
		{name: "refused apply is left to the pipeline", ctx: userCtx(alice()), verb: "apply", decide: deny},
		{name: "refused delete is left to the pipeline", ctx: userCtx(alice()), verb: "delete", decide: deny},
		{name: "the registry itself", ctx: auth.WithSystemContext(context.Background()), verb: "get", decide: deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(tt.decide)
			pdp.err = tt.pdpErr
			rec := &auditCollector{}
			p := newPEP(t, pdp, func(c *Config) { c.Audit = rec })
			in := types.AuthorizeInput{Verb: tt.verb, Kind: v1alpha1.KindPrompt, Namespace: "team", Name: "p", Tag: "v1"}
			if tt.viaList {
				_, _, _ = p.ListFilter(tt.ctx, types.AuthorizeInput{Kind: v1alpha1.KindPrompt, Namespace: "team"})
			} else {
				_ = p.Authorize(tt.ctx, in)
			}
			if tt.wantAction == "" {
				assert.Empty(t, rec.events)
				return
			}
			require.Len(t, rec.events, 1)
			e := rec.events[0]
			assert.Equal(t, tt.wantAction, e.Action)
			assert.Equal(t, audit.OutcomeDenied, e.Outcome)
			assert.Equal(t, v1alpha1.KindPrompt, e.Resource.Kind)
			assert.Equal(t, "team", e.Resource.Namespace)
			assert.Equal(t, "alice-sub", e.Actor.Subject)
			assert.Contains(t, e.Detail, tt.wantContain)
		})
	}
}
