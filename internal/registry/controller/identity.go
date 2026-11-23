package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// IdentityInUseReason is the Ready=False reason of a Deployment whose
// planned workload identity was assigned before. SPIFFE IDs are never reused,
// so its workload is not applied.
const IdentityInUseReason = "IdentityInUse"

// assignIdentity records, before Apply, the workload identity an adapter
// that gives one (types.DeploymentIdentityPlanner) will apply: the
// assignment of the new SPIFFE ID prefix, after revoking the Deployment's
// previous one when it changes (a new agent). The Deployment's internal meta
// takes the prefix and workload, in the same transaction, so a workload is
// never created for an identity the history lacks, and Remove can find it.
//
// It returns the plan when Apply may go ahead. blocked is set, with the
// outcome already persisted, when the prefix was assigned before.
func (c *DeploymentController) assignIdentity(
	ctx context.Context,
	adapter types.DeploymentAdapter,
	input types.ApplyInput,
) (plan *types.PlannedIdentity, blocked bool, err error) {
	planner, ok := adapter.(types.DeploymentIdentityPlanner)
	if !ok {
		return nil, false, nil
	}
	plan, err = planner.PlanIdentity(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("adapter %q plan identity: %w", adapter.Type(), err)
	}
	deployment := input.Deployment
	current := deployment.InternalMeta.ActorSubject
	if plan == nil || plan.SPIFFEIDPrefix == current {
		return plan, false, nil
	}

	change := v1alpha1store.IdentityChange{Assign: identityAssignment(input, plan)}
	if current != "" {
		change.Revoke = []string{current}
	}
	meta := deployment.InternalMeta
	meta.ActorSubject = plan.SPIFFEIDPrefix
	meta.RuntimeNamespace = plan.WorkloadNamespace
	meta.RuntimeName = plan.WorkloadName
	namespace, name := deployment.Metadata.NamespaceOrDefault(), deployment.Metadata.Name
	err = c.deploymentStore().ApplyPatchWithIdentityChange(ctx, namespace, name, v1alpha1store.PatchOpts{}, meta, change)
	if errors.Is(err, v1alpha1store.ErrIdentityAlreadyAssigned) {
		patch := v1alpha1store.PatchOpts{Status: v1alpha1.DeploymentStatusPatcher(func(s *v1alpha1.DeploymentStatus) {
			s.SetCondition(v1alpha1.Condition{
				Type:               "Ready",
				Status:             v1alpha1.ConditionFalse,
				Reason:             IdentityInUseReason,
				Message:            fmt.Sprintf("workload identity %s was assigned before; SPIFFE IDs are never reused", plan.SPIFFEIDPrefix),
				LastTransitionTime: time.Now().UTC(),
			})
		})}
		if err := c.deploymentStore().ApplyPatch(ctx, namespace, name, "", patch); err != nil {
			return nil, false, fmt.Errorf("persist identity conflict: %w", err)
		}
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("record workload identity: %w", err)
	}
	deployment.InternalMeta = meta
	return plan, false, nil
}

func identityAssignment(input types.ApplyInput, plan *types.PlannedIdentity) *v1alpha1store.IdentityEvent {
	deployment := input.Deployment
	event := &v1alpha1store.IdentityEvent{
		SPIFFEIDPrefix:      plan.SPIFFEIDPrefix,
		DeploymentNamespace: deployment.Metadata.NamespaceOrDefault(),
		DeploymentName:      deployment.Metadata.Name,
		DeploymentUID:       deployment.Metadata.UID,
		WorkloadNamespace:   plan.WorkloadNamespace,
		WorkloadName:        plan.WorkloadName,
	}
	if target := input.Target; target != nil {
		meta := target.GetMetadata()
		event.AgentNamespace, event.AgentName, event.AgentTag = meta.NamespaceOrDefault(), meta.Name, meta.Tag
	}
	if input.Runtime != nil {
		event.RuntimeNamespace, event.RuntimeName = input.Runtime.Metadata.NamespaceOrDefault(), input.Runtime.Metadata.Name
	}
	return event
}

// RuntimeUnavailableReason is the Ready=False reason of a deleted Deployment
// whose workload holds an identity but whose Runtime is gone, so its
// teardown cannot run. It is not finalized until the Runtime is back.
const RuntimeUnavailableReason = "RuntimeUnavailable"

func (c *DeploymentController) blockRuntimeUnavailable(ctx context.Context, deployment *types.DeploymentRecord) (string, string, error) {
	ref := deployment.Spec.RuntimeRef
	message := fmt.Sprintf("Runtime %s/%s is gone; the workload %s/%s holds identity %s and is kept until the Runtime is back to remove it",
		refNamespace(ref.Namespace, deployment.Metadata.NamespaceOrDefault()), ref.Name,
		deployment.InternalMeta.RuntimeNamespace, deployment.InternalMeta.RuntimeName, deployment.InternalMeta.ActorSubject)
	patch := v1alpha1store.PatchOpts{Status: v1alpha1.DeploymentStatusPatcher(func(s *v1alpha1.DeploymentStatus) {
		s.SetCondition(v1alpha1.Condition{
			Type:               "Ready",
			Status:             v1alpha1.ConditionFalse,
			Reason:             RuntimeUnavailableReason,
			Message:            message,
			LastTransitionTime: time.Now().UTC(),
		})
	})}
	if err := c.deploymentStore().ApplyPatch(ctx, deployment.Metadata.NamespaceOrDefault(), deployment.Metadata.Name, "", patch); err != nil {
		return "", "", fmt.Errorf("persist runtime unavailable: %w", err)
	}
	return "blocked", message, nil
}

// checkAppliedIdentity refuses an Apply result whose identity differs from
// the one recorded before Apply.
func checkAppliedIdentity(adapter types.DeploymentAdapter, plan *types.PlannedIdentity, result *types.ApplyResult) error {
	if plan == nil || result == nil || result.InternalMeta == nil {
		return nil
	}
	if result.InternalMeta.ActorSubject != plan.SPIFFEIDPrefix {
		return fmt.Errorf("adapter %q applied identity %q but planned %q", adapter.Type(), result.InternalMeta.ActorSubject, plan.SPIFFEIDPrefix)
	}
	return nil
}
