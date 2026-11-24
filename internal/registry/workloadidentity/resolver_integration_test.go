//go:build integration

package workloadidentity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	registrytypes "github.com/agentregistry-dev/agentregistry/pkg/types"
)

// The resolver against the Deployment store's identity records: an assigned
// identity resolves, and stops resolving once it is revoked.
func TestResolverWithIdentityRecords(t *testing.T) {
	ctx := context.Background()
	store := v1alpha1store.NewMutableObjectStore(v1alpha1store.NewTestPool(t), v1alpha1store.TestSchema(), "deployments", v1alpha1store.WithInternalMeta())
	_, err := store.Upsert(ctx, &v1alpha1.Deployment{
		Metadata: v1alpha1.ObjectMeta{Namespace: "default", Name: "credit-desk"},
		Spec: v1alpha1.DeploymentSpec{
			TargetRef:  v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "credit"},
			RuntimeRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Name: "runtime"},
		},
	})
	require.NoError(t, err)
	object, err := store.Get(ctx, "default", "credit-desk", "")
	require.NoError(t, err)
	uid := object.Metadata.UID

	prefix := "spiffe://" + td + "/org/default/agent/credit/deployment/" + uid + "/"
	id := prefix + "instance/" + podUID
	resolver, err := NewResolver(td, store.IdentityHistory)
	require.NoError(t, err)

	_, err = resolver.Resolve(ctx, id, id)
	require.ErrorIs(t, err, ErrUnknown, "before assignment")

	meta := registrytypes.DeploymentInternalMeta{ActorSubject: prefix}
	require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, "default", "credit-desk", v1alpha1store.PatchOpts{}, meta,
		v1alpha1store.IdentityChange{Assign: &v1alpha1store.IdentityEvent{
			SPIFFEIDPrefix: prefix, DeploymentNamespace: "default", DeploymentName: "credit-desk", DeploymentUID: uid,
			AgentNamespace: "default", AgentName: "credit", AgentTag: "1.2.0", RuntimeNamespace: "default", RuntimeName: "runtime",
			WorkloadNamespace: "org-default", WorkloadName: "credit-desk-abc",
		}}))
	res, err := resolver.Resolve(ctx, id, id)
	require.NoError(t, err)
	assert.Equal(t, "credit", res.AgentName)
	assert.Equal(t, uid, res.DeploymentUID)

	require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, "default", "credit-desk", v1alpha1store.PatchOpts{},
		registrytypes.DeploymentInternalMeta{}, v1alpha1store.IdentityChange{Revoke: []string{prefix}}))
	_, err = resolver.Resolve(ctx, id, id)
	require.ErrorIs(t, err, ErrRevoked, "a revoked identity never resolves again")
}
