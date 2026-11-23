//go:build integration

package v1alpha1store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	pkgdb "github.com/agentregistry-dev/agentregistry/pkg/registry/database"
)

func TestRuntimeCannotBeDeletedWhileDeploymentsUseIt(t *testing.T) {
	pool := NewTestPool(t)
	runtimes := NewMutableObjectStore(pool, TestSchema(), "runtimes")
	deployments := NewMutableObjectStore(pool, TestSchema(), "deployments", WithInternalMeta())
	ctx := context.Background()

	for _, name := range []string{"rt", "unused"} {
		_, err := runtimes.Upsert(ctx, &v1alpha1.Runtime{
			Metadata: v1alpha1.ObjectMeta{Namespace: testNS, Name: name},
			Spec:     v1alpha1.RuntimeSpec{Type: "Test"},
		})
		require.NoError(t, err)
	}
	_, err := deployments.Upsert(ctx, &v1alpha1.Deployment{
		Metadata: v1alpha1.ObjectMeta{Namespace: testNS, Name: "desk"},
		Spec: v1alpha1.DeploymentSpec{
			TargetRef:  v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "credit"},
			RuntimeRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Name: "rt"},
		},
	}, UpsertOpts{InitialFinalizers: []string{"test/finalizer"}})
	require.NoError(t, err)

	err = runtimes.Delete(ctx, testNS, "rt", "")
	require.ErrorIs(t, err, ErrReferenced)
	require.ErrorContains(t, err, testNS+"/desk", "the refusal names the Deployments")
	_, err = runtimes.Get(ctx, testNS, "rt", "")
	require.NoError(t, err, "the Runtime is kept")

	// A discovered Deployment is an observation; it doesn't hold its Runtime.
	_, err = deployments.Upsert(ctx, &v1alpha1.Deployment{
		Metadata: v1alpha1.ObjectMeta{Namespace: testNS, Name: "seen", Annotations: map[string]string{
			v1alpha1.DeploymentOriginAnnotation: v1alpha1.DeploymentOriginDiscovered,
		}},
		Spec: v1alpha1.DeploymentSpec{
			TargetRef:  v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "external"},
			RuntimeRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Name: "unused"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, runtimes.Delete(ctx, testNS, "unused", ""), "a Runtime only discovered Deployments point at can go")

	// A terminating Deployment still needs its Runtime for teardown.
	require.NoError(t, deployments.Delete(ctx, testNS, "desk", ""))
	require.ErrorIs(t, runtimes.Delete(ctx, testNS, "rt", ""), ErrReferenced)

	// A Runtime with finalizers may still be marked terminating; it stays
	// readable for the Deployment's teardown.
	require.NoError(t, runtimes.PatchFinalizers(ctx, testNS, "rt", "", func([]string) []string { return []string{"test/finalizer"} }))
	require.NoError(t, runtimes.Delete(ctx, testNS, "rt", ""))
	terminating, err := runtimes.GetLatestIncludingTerminating(ctx, testNS, "rt")
	require.NoError(t, err)
	require.NotNil(t, terminating.Metadata.DeletionTimestamp)
	require.NoError(t, runtimes.PatchFinalizers(ctx, testNS, "rt", "", func([]string) []string { return nil }))
	_, err = runtimes.PurgeFinalized(ctx)
	require.ErrorIs(t, err, ErrReferenced, "but its row stays while the Deployment exists")

	// Once the Deployment is purged, the Runtime can go.
	require.NoError(t, deployments.PatchFinalizers(ctx, testNS, "desk", "", func([]string) []string { return nil }))
	_, err = deployments.PurgeFinalized(ctx)
	require.NoError(t, err)
	purged, err := runtimes.PurgeFinalized(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), purged)
	_, err = runtimes.GetLatestIncludingTerminating(ctx, testNS, "rt")
	require.ErrorIs(t, err, pkgdb.ErrNotFound)
}
