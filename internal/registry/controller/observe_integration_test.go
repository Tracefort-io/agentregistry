//go:build integration

package controller

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// observingDeploymentAdapter reports, on each observation, whatever
// conditions the test set last.
type observingDeploymentAdapter struct {
	*recordingDeploymentAdapter
	observeCalls atomic.Int32
	mu           sync.Mutex
	observed     []v1alpha1.Condition
	observeErr   error
}

func (a *observingDeploymentAdapter) set(conditions ...v1alpha1.Condition) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.observed = conditions
}

func (a *observingDeploymentAdapter) ObserveStatus(context.Context, types.ObserveInput) (*types.ObserveResult, error) {
	a.observeCalls.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.observeErr != nil {
		return nil, a.observeErr
	}
	return &types.ObserveResult{Conditions: append([]v1alpha1.Condition(nil), a.observed...)}, nil
}

func reconcileOnce(t *testing.T, controller *DeploymentController) {
	t.Helper()
	_, err := controller.FullReconcile(context.Background())
	require.NoError(t, err)
	processed, err := controller.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, processed)
}

func TestDeploymentController_ObservesStatusOfUnchangedApply(t *testing.T) {
	stores := newControllerTestStores(t)
	seedMCPServer(t, stores, "weather")
	deployment := seedDeployment(t, stores, "weather-observed", v1alpha1.DesiredStateDeployed)

	adapter := &observingDeploymentAdapter{recordingDeploymentAdapter: &recordingDeploymentAdapter{}}
	controller := newDeploymentTestController(stores, adapter)

	reconcileOnce(t, controller)
	require.Equal(t, int32(1), adapter.applyCalls.Load())
	require.Equal(t, int32(0), adapter.observeCalls.Load(), "a fresh apply is not observed in the same pass")

	// The workload comes up after Apply returned.
	adapter.set(v1alpha1.Condition{Type: "Ready", Status: v1alpha1.ConditionFalse, Reason: "Unavailable", Message: "0/2 replicas available"})
	reconcileOnce(t, controller)
	require.Equal(t, int32(1), adapter.applyCalls.Load(), "unchanged desired input must not call Apply again")
	require.Equal(t, int32(1), adapter.observeCalls.Load())
	ready := loadDeployment(t, stores, deployment.Metadata.Name).Status.GetCondition("Ready")
	require.NotNil(t, ready)
	require.Equal(t, v1alpha1.ConditionFalse, ready.Status)
	require.Equal(t, "Unavailable", ready.Reason)
	unavailableSince := ready.LastTransitionTime

	adapter.set(v1alpha1.Condition{Type: "Ready", Status: v1alpha1.ConditionTrue, Reason: "Available", Message: "2/2 replicas available"})
	reconcileOnce(t, controller)
	ready = loadDeployment(t, stores, deployment.Metadata.Name).Status.GetCondition("Ready")
	require.Equal(t, v1alpha1.ConditionTrue, ready.Status)
	require.Equal(t, "Available", ready.Reason)
	require.True(t, ready.LastTransitionTime.After(unavailableSince) || ready.LastTransitionTime.Equal(unavailableSince))
	availableSince := ready.LastTransitionTime

	// The same observation again leaves the stored status alone.
	reconcileOnce(t, controller)
	require.Equal(t, int32(3), adapter.observeCalls.Load())
	ready = loadDeployment(t, stores, deployment.Metadata.Name).Status.GetCondition("Ready")
	require.Equal(t, availableSince, ready.LastTransitionTime)
	require.Equal(t, int32(1), adapter.applyCalls.Load())
}

func TestDeploymentController_ObserveFailureRetriesWithoutStatusChange(t *testing.T) {
	stores := newControllerTestStores(t)
	seedMCPServer(t, stores, "weather")
	deployment := seedDeployment(t, stores, "weather-observe-error", v1alpha1.DesiredStateDeployed)

	adapter := &observingDeploymentAdapter{recordingDeploymentAdapter: &recordingDeploymentAdapter{}}
	controller := newDeploymentTestController(stores, adapter)
	reconcileOnce(t, controller)
	before := loadDeployment(t, stores, deployment.Metadata.Name).Status.GetCondition("Ready")

	adapter.observeErr = errors.New("runtime API unreachable")
	_, err := controller.FullReconcile(context.Background())
	require.NoError(t, err)
	_, _, err = controller.reconcileKey(context.Background(), deploymentQueueKey{Namespace: "default", Name: deployment.Metadata.Name})
	require.ErrorContains(t, err, "observe status")

	after := loadDeployment(t, stores, deployment.Metadata.Name).Status.GetCondition("Ready")
	require.Equal(t, before.Status, after.Status)
	require.Equal(t, before.Reason, after.Reason)
}
