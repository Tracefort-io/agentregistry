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
