//go:build integration

package v1alpha1store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	registrytypes "github.com/agentregistry-dev/agentregistry/pkg/types"
)

const testPrefix = "spiffe://test.example/org/default/agent/credit/deployment/4b1c1e0e-3f2a-4c55-9d8e-2a7f6c1b9e10/"

func identityStore(t *testing.T) (*Store, string) {
	t.Helper()
	store := NewMutableObjectStore(NewTestPool(t), TestSchema(), "deployments", WithInternalMeta())
	_, err := store.Upsert(context.Background(), &v1alpha1.Deployment{
		Metadata: v1alpha1.ObjectMeta{Namespace: testNS, Name: "desk"},
		Spec: v1alpha1.DeploymentSpec{
			TargetRef:  v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "credit"},
			RuntimeRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Name: "runtime"},
		},
	})
	require.NoError(t, err)
	object, err := store.Get(context.Background(), testNS, "desk", "")
	require.NoError(t, err)
	return store, object.Metadata.UID
}

func assignment(prefix, uid string) *IdentityEvent {
	return &IdentityEvent{
		SPIFFEIDPrefix: prefix, DeploymentNamespace: testNS, DeploymentName: "desk", DeploymentUID: uid,
		AgentNamespace: testNS, AgentName: "credit", AgentTag: "1.0.0", RuntimeNamespace: testNS, RuntimeName: "runtime",
		WorkloadNamespace: "org-default", WorkloadName: "desk-abc",
	}
}

func events(t *testing.T, store *Store, prefix string) []string {
	t.Helper()
	history, err := store.IdentityHistory(context.Background(), prefix)
	require.NoError(t, err)
	out := make([]string, 0, len(history))
	for _, e := range history {
		out = append(out, e.Event)
	}
	return out
}

func TestIdentityEvents_AssignedOnceEver(t *testing.T) {
	store, uid := identityStore(t)
	ctx := context.Background()
	meta := registrytypes.DeploymentInternalMeta{ActorSubject: testPrefix}

	require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{}, meta, IdentityChange{Assign: assignment(testPrefix, uid)}))
	history, err := store.IdentityHistory(ctx, testPrefix)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, IdentityAssigned, history[0].Event)
	require.Equal(t, uid, history[0].DeploymentUID)
	require.Equal(t, "1.0.0", history[0].AgentTag)
	require.False(t, history[0].OccurredAt.IsZero())

	// A second assignment fails, and its patch is rolled back with it.
	other := registrytypes.DeploymentInternalMeta{ActorSubject: testPrefix, RuntimeName: "changed"}
	err = store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{}, other, IdentityChange{Assign: assignment(testPrefix, uid)})
	require.ErrorIs(t, err, ErrIdentityAlreadyAssigned)
	object, err := store.Get(ctx, testNS, "desk", "")
	require.NoError(t, err)
	require.JSONEq(t, `{"actorSubject":"`+testPrefix+`"}`, string(object.InternalMeta))

	// Not even after revocation.
	require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{}, meta, IdentityChange{Revoke: []string{testPrefix}}))
	err = store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{}, meta, IdentityChange{Assign: assignment(testPrefix, uid)})
	require.ErrorIs(t, err, ErrIdentityAlreadyAssigned)
	require.Equal(t, []string{IdentityAssigned, IdentityRevoked}, events(t, store, testPrefix))
}

func TestIdentityEvents_RevocationCopiesAssignmentAndHappensOnce(t *testing.T) {
	store, uid := identityStore(t)
	ctx := context.Background()
	meta := registrytypes.DeploymentInternalMeta{ActorSubject: testPrefix}
	require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{}, meta, IdentityChange{Assign: assignment(testPrefix, uid)}))

	for range 2 {
		require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{}, meta, IdentityChange{Revoke: []string{testPrefix}}))
	}
	history, err := store.IdentityHistory(ctx, testPrefix)
	require.NoError(t, err)
	require.Len(t, history, 2, "a retried revocation records nothing more")
	revoked := history[1]
	require.Equal(t, IdentityRevoked, revoked.Event)
	require.Equal(t, uid, revoked.DeploymentUID)
	require.Equal(t, "credit", revoked.AgentName)
	require.Equal(t, "desk-abc", revoked.WorkloadName)

	// A prefix that was never assigned has nothing to revoke.
	unknown := "spiffe://test.example/org/default/agent/none/deployment/x/"
	require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{}, meta, IdentityChange{Revoke: []string{unknown}}))
	require.Empty(t, events(t, store, unknown))
}

func TestIdentityEvents_AppendOnly(t *testing.T) {
	store, uid := identityStore(t)
	ctx := context.Background()
	require.NoError(t, store.ApplyPatchWithIdentityChange(ctx, testNS, "desk", PatchOpts{},
		registrytypes.DeploymentInternalMeta{ActorSubject: testPrefix}, IdentityChange{Assign: assignment(testPrefix, uid)}))

	for _, statement := range []string{
		`UPDATE ` + store.identityEvents + ` SET agent_name = 'other'`,
		`DELETE FROM ` + store.identityEvents,
		`TRUNCATE ` + store.identityEvents,
	} {
		_, err := store.pool.Exec(ctx, statement)
		require.ErrorContains(t, err, "append-only", statement)
	}
	require.Equal(t, []string{IdentityAssigned}, events(t, store, testPrefix))
}

func TestIdentityEvents_RequireDeploymentsStore(t *testing.T) {
	runtimes := NewMutableObjectStore(NewTestPool(t), TestSchema(), "runtimes")
	err := runtimes.ApplyPatchWithIdentityChange(context.Background(), testNS, "x", PatchOpts{}, struct{}{}, IdentityChange{})
	require.ErrorContains(t, err, "internal meta")
}
