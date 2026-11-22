//go:build integration

package resource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	arv0 "github.com/agentregistry-dev/agentregistry/pkg/api/v0"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/resource"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var errNeedsApproval = errors.New("approval required")

// stager holds denials that are errNeedsApproval.
type stager struct{ inputs []types.ApprovalStageInput }

func (s *stager) Holds(_ context.Context, _ string, denial error) bool {
	return errors.Is(denial, errNeedsApproval)
}

func (s *stager) Stage(_ context.Context, in types.ApprovalStageInput) (string, bool, error) {
	if !errors.Is(in.Denial, errNeedsApproval) {
		return "", false, nil
	}
	s.inputs = append(s.inputs, in)
	return "arq_1", true, nil
}

func TestApply_HoldsChangesThatNeedApproval(t *testing.T) {
	pool := v1alpha1store.NewTestPool(t)
	store := v1alpha1store.NewStore(pool, v1alpha1store.TestSchema(), "agents")
	st := &stager{}
	authorize := func(_ context.Context, in resource.AuthorizeInput) error {
		switch in.Name {
		case "needs-approval":
			return errNeedsApproval
		case "refused":
			return errors.New("forbidden")
		}
		return nil
	}
	_, api := humatest.New(t)
	resource.RegisterApply(api, resource.ApplyConfig{
		BasePrefix:  "/v0",
		Stores:      map[string]*v1alpha1store.Store{v1alpha1.KindAgent: store},
		Authorizers: map[string]func(context.Context, resource.AuthorizeInput) error{v1alpha1.KindAgent: authorize},
		Approvals:   st,
	})
	results := func(method, query, body string) []arv0.ApplyResult {
		t.Helper()
		resp := api.Do(method, "/v0/apply"+query, "Content-Type: application/yaml", strings.NewReader(body))
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		var out struct {
			Results []arv0.ApplyResult `json:"results"`
		}
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
		return out.Results
	}

	got := results(http.MethodPost, "", agentDoc("needs-approval", "")+"---\n"+agentDoc("refused", "")+"---\n"+agentDoc("allowed", ""))
	require.Len(t, got, 3)
	assert.Equal(t, arv0.ApplyStatusPendingApproval, got[0].Status)
	assert.Equal(t, "arq_1", got[0].ApprovalRequest)
	assert.Equal(t, "latest", got[0].Tag, "the defaulted tag")
	assert.Equal(t, arv0.ApplyStatusFailed, got[1].Status, "an ordinary refusal stays a failure")
	assert.Equal(t, arv0.ApplyStatusCreated, got[2].Status)

	require.Len(t, st.inputs, 1)
	assert.Equal(t, "apply", st.inputs[0].Verb)
	assert.Equal(t, "needs-approval", st.inputs[0].Object.GetMetadata().Name)
	_, err := store.GetLatest(t.Context(), "default", "needs-approval")
	require.Error(t, err, "nothing is written while held")

	got = results(http.MethodPost, "?dryRun=true", agentDoc("needs-approval", ""))
	assert.Equal(t, arv0.ApplyStatusFailed, got[0].Status, "a dry run is never held")
	assert.Len(t, st.inputs, 1)

	got = results(http.MethodDelete, "", agentDoc("needs-approval", "latest"))
	assert.Equal(t, arv0.ApplyStatusPendingApproval, got[0].Status)
	require.Len(t, st.inputs, 2)
	assert.Equal(t, "delete", st.inputs[1].Verb)
	assert.Nil(t, st.inputs[1].Object)
}

// TestApply_RefusesADeletedTagBeforeHoldingOrDryRunning pins that an apply
// to a deleted tag fails at once — when it would be held for approval, in a
// dry run and applied directly — instead of asking an approver for a change
// that cannot be applied once approved. The deleted tag is reported before
// the other checks: here every document also has a dangling reference.
func TestApply_RefusesADeletedTagBeforeHoldingOrDryRunning(t *testing.T) {
	pool := v1alpha1store.NewTestPool(t)
	store := v1alpha1store.NewStore(pool, v1alpha1store.TestSchema(), "agents")
	for _, name := range []string{"held", "direct"} {
		_, err := store.Upsert(t.Context(), &v1alpha1.Agent{
			Metadata: v1alpha1.ObjectMeta{Namespace: "default", Name: name},
			Spec:     v1alpha1.AgentSpec{Title: "t"},
		})
		require.NoError(t, err)
		require.NoError(t, store.DeleteAllTags(t.Context(), "default", name))
	}
	st := &stager{}
	authorize := func(_ context.Context, in resource.AuthorizeInput) error {
		if in.Name == "held" {
			return errNeedsApproval
		}
		return nil
	}
	_, api := humatest.New(t)
	resource.RegisterApply(api, resource.ApplyConfig{
		BasePrefix:  "/v0",
		Stores:      map[string]*v1alpha1store.Store{v1alpha1.KindAgent: store},
		Authorizers: map[string]func(context.Context, resource.AuthorizeInput) error{v1alpha1.KindAgent: authorize},
		Approvals:   st,
		Resolver:    func(context.Context, v1alpha1.ResourceRef) error { return v1alpha1.ErrDanglingRef },
	})
	// withRef adds a reference the resolver above reports as dangling.
	withRef := func(doc string) string {
		return doc + "  mcpServers:\n    - kind: MCPServer\n      name: missing\n      tag: latest\n"
	}
	apply := func(query, body string) arv0.ApplyResult {
		t.Helper()
		resp := api.Post("/v0/apply"+query, "Content-Type: application/yaml", strings.NewReader(body))
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		var out struct {
			Results []arv0.ApplyResult `json:"results"`
		}
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
		require.Len(t, out.Results, 1)
		return out.Results[0]
	}

	tests := []struct {
		name, query, doc string
	}{
		{"held for approval", "", withRef(agentDoc("held", ""))},
		{"held for approval, explicit tag", "", withRef(agentDoc("held", "latest"))},
		{"dry run", "?dryRun=true", withRef(agentDoc("direct", ""))},
		{"applied directly", "", withRef(agentDoc("direct", ""))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := apply(tt.query, tt.doc)
			assert.Equal(t, arv0.ApplyStatusFailed, got.Status)
			assert.Contains(t, got.Error, "was deleted; versions are immutable")
		})
	}
	assert.Empty(t, st.inputs, "nothing is held for approval")

	// On a new tag the dangling reference is what fails.
	got := apply("", withRef(agentDoc("held", "v2")))
	assert.Equal(t, arv0.ApplyStatusFailed, got.Status)
	assert.Contains(t, got.Error, "refs")
	assert.NotContains(t, got.Error, "was deleted")
	assert.Empty(t, st.inputs)

	// Without it, a new tag is held as usual.
	got = apply("", agentDoc("held", "v2"))
	assert.Equal(t, arv0.ApplyStatusPendingApproval, got.Status)
	require.Len(t, st.inputs, 1)
}
