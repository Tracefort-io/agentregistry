//go:build integration

package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var errTestRemove = errors.New("runtime teardown failed")

// planningDeploymentAdapter gives each Deployment an identity built from its
// agent and UID, and checks at Apply time that the assignment is already
// recorded.
type planningDeploymentAdapter struct {
	*recordingDeploymentAdapter
	store             *v1alpha1store.Store
	assignedAtApply   atomic.Bool
	reportWrongPrefix bool
}

func plannedPrefix(input types.ApplyInput) string {
	return "spiffe://test.example/org/default/agent/" + input.Target.GetMetadata().Name +
		"/deployment/" + input.Deployment.Metadata.UID + "/"
}

func (a *planningDeploymentAdapter) PlanIdentity(_ context.Context, input types.ApplyInput) (*types.PlannedIdentity, error) {
	return &types.PlannedIdentity{
		SPIFFEIDPrefix:    plannedPrefix(input),
		WorkloadNamespace: "org-default",
		WorkloadName:      "w-" + input.Deployment.Metadata.Name,
	}, nil
}

func (a *planningDeploymentAdapter) Apply(ctx context.Context, input types.ApplyInput) (*types.ApplyResult, error) {
	a.applyCalls.Add(1)
	history, err := a.store.IdentityHistory(ctx, plannedPrefix(input))
	if err != nil {
		return nil, err
	}
	a.assignedAtApply.Store(len(history) > 0 && history[len(history)-1].Event == v1alpha1store.IdentityAssigned)
	prefix := plannedPrefix(input)
	if a.reportWrongPrefix {
		prefix += "other/"
	}
	return &types.ApplyResult{
		InternalMeta: &types.DeploymentInternalMeta{ActorSubject: prefix, RuntimeNamespace: "org-default", RuntimeName: "w-" + input.Deployment.Metadata.Name},
		Conditions:   []v1alpha1.Condition{{Type: "Ready", Status: v1alpha1.ConditionTrue, Reason: "Applied"}},
	}, nil
}

func newPlanningAdapter(stores map[string]*v1alpha1store.Store) *planningDeploymentAdapter {
	return &planningDeploymentAdapter{recordingDeploymentAdapter: &recordingDeploymentAdapter{}, store: stores[v1alpha1.KindDeployment]}
}

func upsertAgentDeployment(t *testing.T, stores map[string]*v1alpha1store.Store, name, agentName, desiredState string) {
	t.Helper()
	_, err := stores[v1alpha1.KindDeployment].Upsert(context.Background(), &v1alpha1.Deployment{
		Metadata: v1alpha1.ObjectMeta{Namespace: "default", Name: name},
		Spec: v1alpha1.DeploymentSpec{
			TargetRef:    v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: agentName, Tag: v1alpha1store.DefaultTag()},
			RuntimeRef:   v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Name: "test-runtime"},
			DesiredState: desiredState,
		},
	}, v1alpha1store.UpsertOpts{InitialFinalizers: []string{DeploymentControllerFinalizer}})
	require.NoError(t, err)
}

func identityHistory(t *testing.T, stores map[string]*v1alpha1store.Store, prefix string) []string {
	t.Helper()
	history, err := stores[v1alpha1.KindDeployment].IdentityHistory(context.Background(), prefix)
	require.NoError(t, err)
	events := make([]string, 0, len(history))
	for _, e := range history {
		events = append(events, e.Event)
	}
	return events
}

func agentPrefix(agent, uid string) string {
	return "spiffe://test.example/org/default/agent/" + agent + "/deployment/" + uid + "/"
}

func TestDeploymentController_AssignsIdentityBeforeApply(t *testing.T) {
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	deployment := seedAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateDeployed)
	adapter := newPlanningAdapter(stores)
	controller := newDeploymentTestController(stores, adapter)

	reconcileOnce(t, controller)
	require.Equal(t, int32(1), adapter.applyCalls.Load())
	require.True(t, adapter.assignedAtApply.Load(), "the assignment is recorded before Apply runs")

	prefix := agentPrefix("credit", deployment.Metadata.UID)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, prefix))
	history, err := stores[v1alpha1.KindDeployment].IdentityHistory(context.Background(), prefix)
	require.NoError(t, err)
	got := history[0]
	require.Equal(t, deployment.Metadata.UID, got.DeploymentUID)
	require.Equal(t, "credit", got.AgentName)
	require.Equal(t, "test-runtime", got.RuntimeName)
	require.Equal(t, "w-credit-desk", got.WorkloadName)
	require.Equal(t, prefix, loadDeploymentRecord(t, stores, "credit-desk").InternalMeta.ActorSubject)

	reconcileOnce(t, controller)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, prefix), "an unchanged apply records nothing")
}

func TestDeploymentController_RefusesIdentityAssignedBefore(t *testing.T) {
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	deployment := seedAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateDeployed)
	other := seedAgentDeployment(t, stores, "other-desk", "credit", v1alpha1.DesiredStateUndeployed)

	// Something already holds the prefix credit-desk would get.
	prefix := agentPrefix("credit", deployment.Metadata.UID)
	require.NoError(t, stores[v1alpha1.KindDeployment].ApplyPatchWithIdentityChange(context.Background(), "default", other.Metadata.Name,
		v1alpha1store.PatchOpts{}, types.DeploymentInternalMeta{ActorSubject: prefix}, v1alpha1store.IdentityChange{Assign: &v1alpha1store.IdentityEvent{
			SPIFFEIDPrefix: prefix, DeploymentNamespace: "default", DeploymentName: other.Metadata.Name, DeploymentUID: other.Metadata.UID,
			AgentNamespace: "default", AgentName: "credit", RuntimeNamespace: "default", RuntimeName: "test-runtime",
			WorkloadNamespace: "org-default", WorkloadName: "w-other",
		}}))

	adapter := newPlanningAdapter(stores)
	controller := newDeploymentTestController(stores, adapter)
	outcome, _, err := controller.reconcileKey(context.Background(), deploymentQueueKey{Namespace: "default", Name: "credit-desk"})
	require.NoError(t, err)
	require.Equal(t, "blocked", outcome)
	require.Equal(t, int32(0), adapter.applyCalls.Load(), "no workload for an identity assigned before")

	ready := loadDeployment(t, stores, "credit-desk").Status.GetCondition("Ready")
	require.NotNil(t, ready)
	require.Equal(t, v1alpha1.ConditionFalse, ready.Status)
	require.Equal(t, IdentityInUseReason, ready.Reason)
	require.Empty(t, loadDeploymentRecord(t, stores, "credit-desk").InternalMeta.ActorSubject)
}

func TestDeploymentController_UndeployKeepsIdentity(t *testing.T) {
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	deployment := seedAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateDeployed)
	adapter := newPlanningAdapter(stores)
	controller := newDeploymentTestController(stores, adapter)
	reconcileOnce(t, controller)
	prefix := agentPrefix("credit", deployment.Metadata.UID)

	upsertAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateUndeployed)
	reconcileOnce(t, controller)
	require.Equal(t, int32(1), adapter.removeCalls.Load())
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, prefix), "undeploy revokes nothing")

	upsertAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateDeployed)
	reconcileOnce(t, controller)
	require.Equal(t, int32(2), adapter.applyCalls.Load(), "the same Deployment redeploys")
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, prefix), "with the identity it kept")
	require.Equal(t, prefix, loadDeploymentRecord(t, stores, "credit-desk").InternalMeta.ActorSubject)
}

func TestDeploymentController_NewAgentRevokesOldIdentity(t *testing.T) {
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	seedAgent(t, stores, "fraud", nil)
	deployment := seedAgentDeployment(t, stores, "desk", "credit", v1alpha1.DesiredStateDeployed)
	adapter := newPlanningAdapter(stores)
	controller := newDeploymentTestController(stores, adapter)
	reconcileOnce(t, controller)

	upsertAgentDeployment(t, stores, "desk", "fraud", v1alpha1.DesiredStateDeployed)
	reconcileOnce(t, controller)

	oldPrefix, newPrefix := agentPrefix("credit", deployment.Metadata.UID), agentPrefix("fraud", deployment.Metadata.UID)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned, v1alpha1store.IdentityRevoked}, identityHistory(t, stores, oldPrefix))
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, newPrefix))
	require.True(t, adapter.assignedAtApply.Load())

	// The old identity can never come back, even to the same Deployment.
	upsertAgentDeployment(t, stores, "desk", "credit", v1alpha1.DesiredStateDeployed)
	outcome, _, err := controller.reconcileKey(context.Background(), deploymentQueueKey{Namespace: "default", Name: "desk"})
	require.NoError(t, err)
	require.Equal(t, "blocked", outcome)
	require.Equal(t, IdentityInUseReason, loadDeployment(t, stores, "desk").Status.GetCondition("Ready").Reason)
}

func TestDeploymentController_DeleteRevokesIdentityOnce(t *testing.T) {
	ctx := context.Background()
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	deployment := seedAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateDeployed)
	adapter := newPlanningAdapter(stores)
	controller := newDeploymentTestController(stores, adapter)
	reconcileOnce(t, controller)
	prefix := agentPrefix("credit", deployment.Metadata.UID)

	// The first teardown attempt fails; the retry succeeds.
	adapter.removeErr = errTestRemove
	require.NoError(t, stores[v1alpha1.KindDeployment].Delete(ctx, "default", "credit-desk", ""))
	_, _, err := controller.reconcileKey(ctx, deploymentQueueKey{Namespace: "default", Name: "credit-desk"})
	require.Error(t, err)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, prefix), "no revocation before teardown completes")

	adapter.removeErr = nil
	_, _, err = controller.reconcileKey(ctx, deploymentQueueKey{Namespace: "default", Name: "credit-desk"})
	require.NoError(t, err)
	requireDeploymentMissing(t, stores, "credit-desk")
	require.Equal(t, []string{v1alpha1store.IdentityAssigned, v1alpha1store.IdentityRevoked}, identityHistory(t, stores, prefix))

	// A new Deployment with the same name has a new UID, so a new identity.
	recreated := seedAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateDeployed)
	require.NotEqual(t, deployment.Metadata.UID, recreated.Metadata.UID)
	reconcileOnce(t, controller)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, agentPrefix("credit", recreated.Metadata.UID)))
}

func TestDeploymentController_KeepsDeletedDeploymentWithIdentityUntilRuntimeIsBack(t *testing.T) {
	ctx := context.Background()
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	adapter := newPlanningAdapter(stores)
	controller := newDeploymentTestController(stores, adapter)

	// A Deployment holding an identity whose Runtime is gone (it can no
	// longer be deleted while used; this one never existed).
	_, err := stores[v1alpha1.KindDeployment].Upsert(ctx, &v1alpha1.Deployment{
		Metadata: v1alpha1.ObjectMeta{Namespace: "default", Name: "orphan-desk"},
		Spec: v1alpha1.DeploymentSpec{
			TargetRef:  v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "credit", Tag: v1alpha1store.DefaultTag()},
			RuntimeRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Name: "later-runtime"},
		},
	}, v1alpha1store.UpsertOpts{InitialFinalizers: []string{DeploymentControllerFinalizer}})
	require.NoError(t, err)
	deployment := loadDeployment(t, stores, "orphan-desk")
	prefix := agentPrefix("credit", deployment.Metadata.UID)
	require.NoError(t, stores[v1alpha1.KindDeployment].ApplyPatchWithIdentityChange(ctx, "default", "orphan-desk", v1alpha1store.PatchOpts{},
		types.DeploymentInternalMeta{ActorSubject: prefix, RuntimeNamespace: "org-default", RuntimeName: "w-orphan-desk"},
		v1alpha1store.IdentityChange{Assign: &v1alpha1store.IdentityEvent{
			SPIFFEIDPrefix: prefix, DeploymentNamespace: "default", DeploymentName: "orphan-desk", DeploymentUID: deployment.Metadata.UID,
			AgentNamespace: "default", AgentName: "credit", RuntimeNamespace: "default", RuntimeName: "later-runtime",
			WorkloadNamespace: "org-default", WorkloadName: "w-orphan-desk",
		}}))
	require.NoError(t, stores[v1alpha1.KindDeployment].Delete(ctx, "default", "orphan-desk", ""))

	outcome, _, err := controller.reconcileKey(ctx, deploymentQueueKey{Namespace: "default", Name: "orphan-desk"})
	require.NoError(t, err)
	require.Equal(t, "blocked", outcome)
	require.Zero(t, adapter.removeCalls.Load())
	kept := loadDeployment(t, stores, "orphan-desk")
	require.NotNil(t, kept.Metadata.DeletionTimestamp, "kept, still terminating")
	require.Equal(t, RuntimeUnavailableReason, kept.Status.GetCondition("Ready").Reason)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, prefix), "not revoked while its workload may run")

	// With its Runtime back, the teardown runs, the identity is revoked and
	// the Deployment is purged.
	_, err = stores[v1alpha1.KindRuntime].Upsert(ctx, &v1alpha1.Runtime{
		Metadata: v1alpha1.ObjectMeta{Namespace: "default", Name: "later-runtime"},
		Spec:     v1alpha1.RuntimeSpec{Type: "Test"},
	})
	require.NoError(t, err)
	_, _, err = controller.reconcileKey(ctx, deploymentQueueKey{Namespace: "default", Name: "orphan-desk"})
	require.NoError(t, err)
	require.Equal(t, int32(1), adapter.removeCalls.Load())
	requireDeploymentMissing(t, stores, "orphan-desk")
	require.Equal(t, []string{v1alpha1store.IdentityAssigned, v1alpha1store.IdentityRevoked}, identityHistory(t, stores, prefix))
}

func TestDeploymentController_WithdrawsGrantsBeforeRecordingRevocation(t *testing.T) {
	ctx := context.Background()
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	seedAgent(t, stores, "fraud", nil)
	deployment := seedAgentDeployment(t, stores, "desk", "credit", v1alpha1.DesiredStateDeployed)
	adapter := newPlanningAdapter(stores)
	controller := newDeploymentTestController(stores, adapter)
	var withdrawn []string
	var changes int
	controller.AfterIdentityChanged = func(context.Context) { changes++ }
	controller.BeforeIdentityRevoked = func(_ context.Context, prefix string) error {
		// The revocation isn't recorded yet when grants are withdrawn.
		require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, prefix))
		withdrawn = append(withdrawn, prefix)
		return nil
	}
	reconcileOnce(t, controller)
	require.Equal(t, 1, changes, "assignment reported")
	credit := agentPrefix("credit", deployment.Metadata.UID)

	// Moving to another agent withdraws the old identity's grants first.
	upsertAgentDeployment(t, stores, "desk", "fraud", v1alpha1.DesiredStateDeployed)
	reconcileOnce(t, controller)
	require.Equal(t, []string{credit}, withdrawn)
	require.Equal(t, 2, changes)

	// A failure to withdraw stops the revocation; it is retried.
	controller.BeforeIdentityRevoked = func(context.Context, string) error { return errors.New("openbao unreachable") }
	require.NoError(t, stores[v1alpha1.KindDeployment].Delete(ctx, "default", "desk", ""))
	_, _, err := controller.reconcileKey(ctx, deploymentQueueKey{Namespace: "default", Name: "desk"})
	require.ErrorContains(t, err, "withdraw grants")
	fraud := agentPrefix("fraud", deployment.Metadata.UID)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned}, identityHistory(t, stores, fraud), "not revoked while grants may remain")

	controller.BeforeIdentityRevoked = func(_ context.Context, prefix string) error { withdrawn = append(withdrawn, prefix); return nil }
	_, _, err = controller.reconcileKey(ctx, deploymentQueueKey{Namespace: "default", Name: "desk"})
	require.NoError(t, err)
	require.Equal(t, []string{credit, fraud}, withdrawn)
	require.Equal(t, []string{v1alpha1store.IdentityAssigned, v1alpha1store.IdentityRevoked}, identityHistory(t, stores, fraud))
	require.Equal(t, 3, changes)
}

func TestDeploymentController_RefusesApplyWithUnplannedIdentity(t *testing.T) {
	stores := newControllerTestStores(t)
	seedAgent(t, stores, "credit", nil)
	seedAgentDeployment(t, stores, "credit-desk", "credit", v1alpha1.DesiredStateDeployed)
	adapter := newPlanningAdapter(stores)
	adapter.reportWrongPrefix = true
	controller := newDeploymentTestController(stores, adapter)

	_, _, err := controller.reconcileKey(context.Background(), deploymentQueueKey{Namespace: "default", Name: "credit-desk"})
	require.ErrorContains(t, err, "applied identity")
}
