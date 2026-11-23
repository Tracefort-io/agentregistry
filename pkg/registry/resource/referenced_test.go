package resource

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	arv0 "github.com/agentregistry-dev/agentregistry/pkg/api/v0"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

// A delete the store refuses because the object is still used is a conflict
// naming the users, on both the per-kind and the batch path.
func TestReferencedDeleteIsAConflict(t *testing.T) {
	storeErr := fmt.Errorf("hard delete: %w", fmt.Errorf("%w: runtime default/rt is still used by deployments default/desk",
		v1alpha1store.ErrReferenced))
	ae := &applyError{Stage: stageDelete, Err: storeErr, Referenced: errors.Is(storeErr, v1alpha1store.ErrReferenced)}
	require.True(t, ae.Referenced)

	err := mapApplyErrorToHuma(ae, "Runtime", "default", "rt", "")
	var status huma.StatusError
	require.ErrorAs(t, err, &status)
	assert.Equal(t, http.StatusConflict, status.GetStatus())
	assert.Contains(t, err.Error(), "runtime default/rt is still used by deployments default/desk; delete them first")

	res := failResult(arv0.ApplyResult{Kind: "Runtime", Namespace: "default", Name: "rt"}, ae)
	assert.Equal(t, arv0.ApplyStatusFailed, res.Status)
	assert.Equal(t, "runtime default/rt is still used by deployments default/desk; delete them first", res.Error)
}
