package controller

import (
	"context"
	"fmt"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// observe refreshes the status of an applied Deployment whose desired input
// is unchanged, for adapters that report convergence after Apply
// (types.DeploymentStatusObserver). The controller is the only writer: it
// persists the observed conditions, and only when they differ from the
// stored ones.
func (c *DeploymentController) observe(
	ctx context.Context,
	adapter types.DeploymentAdapter,
	deployment *types.DeploymentRecord,
	runtime *v1alpha1.Runtime,
) (string, string, error) {
	observer, ok := adapter.(types.DeploymentStatusObserver)
	if !ok {
		return "unchanged", "deployment desired input unchanged", nil
	}
	result, err := observer.ObserveStatus(ctx, types.ObserveInput{Deployment: deployment, Runtime: runtime})
	if err != nil {
		return "", "", fmt.Errorf("adapter %q observe status: %w", adapter.Type(), err)
	}
	if result == nil || !conditionsChanged(deployment.Status.Conditions, result.Conditions) {
		return "unchanged", "deployment status unchanged", nil
	}
	patch := v1alpha1store.PatchOpts{
		Status: v1alpha1.DeploymentStatusPatcher(func(s *v1alpha1.DeploymentStatus) {
			for _, cond := range result.Conditions {
				s.SetCondition(cond)
			}
		}),
	}
	if err := c.deploymentStore().ApplyPatch(ctx, deployment.Metadata.NamespaceOrDefault(), deployment.Metadata.Name, "", patch); err != nil {
		return "", "", fmt.Errorf("persist observed status: %w", err)
	}
	return "observed", "deployment status updated", nil
}

// conditionsChanged reports whether merging observed into current would change
// any condition's Status, Reason or Message. LastTransitionTime is not
// compared: SetCondition keeps it while a condition's Status is unchanged.
func conditionsChanged(current, observed []v1alpha1.Condition) bool {
	for _, want := range observed {
		found := false
		for _, have := range current {
			if have.Type != want.Type {
				continue
			}
			found = true
			if have.Status != want.Status || have.Reason != want.Reason || have.Message != want.Message {
				return true
			}
			break
		}
		if !found {
			return true
		}
	}
	return false
}
