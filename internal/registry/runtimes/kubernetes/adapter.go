package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

type adapter struct {
	newClient func() (workloadClient, error)
}

var (
	_ types.DeploymentAdapter         = (*adapter)(nil)
	_ types.DeploymentStatusObserver  = (*adapter)(nil)
	_ types.DeploymentIdentityPlanner = (*adapter)(nil)
)

// PlanIdentity returns the identity Apply will give the workload, from the
// same translation Apply uses, without calling Kubernetes. Input Apply would
// refuse gives no identity.
func (a *adapter) PlanIdentity(_ context.Context, in types.ApplyInput) (*types.PlannedIdentity, error) {
	rcfg, err := decodeRuntimeConfig(in.Runtime.Spec.Config)
	if err != nil {
		return nil, nil
	}
	dcfg, err := decodeDeployConfig(in.Deployment.Spec.RuntimeConfig)
	if err != nil {
		return nil, nil
	}
	w, err := buildWorkload(in, rcfg, dcfg)
	if err != nil {
		if errors.Is(err, errInvalidTarget) {
			return nil, nil
		}
		return nil, err
	}
	return &types.PlannedIdentity{SPIFFEIDPrefix: w.actorSubject, WorkloadNamespace: w.namespace, WorkloadName: w.name}, nil
}

// New returns the KubernetesWorkload adapter. It reaches the cluster with the
// registry's in-cluster ServiceAccount, which needs write access only in the
// org namespaces (bound when an org is onboarded).
func New() types.DeploymentAdapter {
	return &adapter{newClient: inClusterClient()}
}

func (a *adapter) Type() string { return RuntimeType }

// SupportedTargetKinds is Agents only: MCP servers are not run by this
// runtime yet.
func (a *adapter) SupportedTargetKinds() []string { return []string{v1alpha1.KindAgent} }

func (a *adapter) Apply(ctx context.Context, in types.ApplyInput) (*types.ApplyResult, error) {
	now := time.Now().UTC()
	rcfg, err := decodeRuntimeConfig(in.Runtime.Spec.Config)
	if err != nil {
		return failedApplyResult("InvalidRuntimeConfig", err.Error(), now), nil
	}
	dcfg, err := decodeDeployConfig(in.Deployment.Spec.RuntimeConfig)
	if err != nil {
		return failedApplyResult("InvalidDeployConfig", err.Error(), now), nil
	}
	w, err := buildWorkload(in, rcfg, dcfg)
	if err != nil {
		if errors.Is(err, errInvalidTarget) {
			return failedApplyResult("InvalidTarget", err.Error(), now), nil
		}
		return nil, err
	}
	client, err := a.newClient()
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes client: %w", err)
	}
	if err := client.apply(ctx, w); err != nil {
		return nil, err
	}
	protocol := v1alpha1.AgentProtocolA2A
	if agent, ok := in.Target.(*v1alpha1.Agent); ok && agent.Spec.Source.Protocol != nil {
		protocol = *agent.Spec.Source.Protocol
	}
	return &types.ApplyResult{
		Conditions: []v1alpha1.Condition{{
			Type:               "Ready",
			Status:             v1alpha1.ConditionFalse,
			Reason:             "Progressing",
			Message:            fmt.Sprintf("waiting for %d replicas of %s/%s", dcfg.replicas(), w.namespace, w.name),
			LastTransitionTime: now,
		}},
		InternalMeta: &types.DeploymentInternalMeta{
			RuntimeID:         w.name,
			RuntimeName:       w.name,
			RuntimeNamespace:  w.namespace,
			RuntimeResourceID: w.namespace + "/" + w.name,
			ActorSubject:      w.actorSubject,
			AppProtocol:       protocol,
		},
		Runtime: &v1alpha1.DeploymentRuntimeStatus{ID: w.name, Name: w.name, ResourceID: w.namespace + "/" + w.name},
	}, nil
}

// ObserveStatus reports Ready from the Kubernetes Deployment: True once every
// desired replica runs the current template and is available.
func (a *adapter) ObserveStatus(ctx context.Context, in types.ObserveInput) (*types.ObserveResult, error) {
	namespace, name := in.Deployment.InternalMeta.RuntimeNamespace, in.Deployment.InternalMeta.RuntimeName
	if namespace == "" || name == "" {
		// A failed Apply created nothing; its conditions stand.
		return nil, nil
	}
	client, err := a.newClient()
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes client: %w", err)
	}
	deployment, err := client.getDeployment(ctx, namespace, name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &types.ObserveResult{Conditions: []v1alpha1.Condition{{
				Type:    "Ready",
				Status:  v1alpha1.ConditionFalse,
				Reason:  "NotFound",
				Message: fmt.Sprintf("Deployment %s/%s does not exist", namespace, name),
			}}}, nil
		}
		return nil, err
	}
	return &types.ObserveResult{Conditions: []v1alpha1.Condition{readyCondition(deployment)}}, nil
}

func readyCondition(d *appsv1.Deployment) v1alpha1.Condition {
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	message := fmt.Sprintf("%d/%d replicas available", d.Status.AvailableReplicas, desired)
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse {
			return v1alpha1.Condition{Type: "Ready", Status: v1alpha1.ConditionFalse, Reason: c.Reason, Message: message + ": " + c.Message}
		}
		if c.Type == appsv1.DeploymentReplicaFailure && c.Status == corev1.ConditionTrue {
			return v1alpha1.Condition{Type: "Ready", Status: v1alpha1.ConditionFalse, Reason: "ReplicaFailure", Message: message + ": " + c.Message}
		}
	}
	current := d.Status.ObservedGeneration >= d.Generation
	if current && d.Status.UpdatedReplicas == desired && d.Status.AvailableReplicas == desired && d.Status.Replicas == desired {
		return v1alpha1.Condition{Type: "Ready", Status: v1alpha1.ConditionTrue, Reason: "Available", Message: message}
	}
	return v1alpha1.Condition{Type: "Ready", Status: v1alpha1.ConditionFalse, Reason: "Progressing", Message: message}
}

func (a *adapter) Remove(ctx context.Context, in types.RemoveInput) (*types.RemoveResult, error) {
	now := time.Now().UTC()
	namespace, name := in.Deployment.InternalMeta.RuntimeNamespace, in.Deployment.InternalMeta.RuntimeName
	if namespace != "" && name != "" {
		client, err := a.newClient()
		if err != nil {
			return nil, fmt.Errorf("build Kubernetes client: %w", err)
		}
		if err := client.remove(ctx, namespace, name); err != nil {
			return nil, fmt.Errorf("remove %s/%s: %w", namespace, name, err)
		}
	}
	return &types.RemoveResult{Conditions: []v1alpha1.Condition{{
		Type:               "Ready",
		Status:             v1alpha1.ConditionFalse,
		Reason:             "Removed",
		Message:            "workload removed",
		LastTransitionTime: now,
	}}}, nil
}

func (a *adapter) Logs(ctx context.Context, in types.LogsInput) (<-chan types.LogLine, error) {
	if in.Deployment == nil {
		return nil, fmt.Errorf("%s logs: deployment is required", RuntimeType)
	}
	namespace, name := in.Deployment.InternalMeta.RuntimeNamespace, in.Deployment.InternalMeta.RuntimeName
	if namespace == "" || name == "" {
		return nil, fmt.Errorf("%s logs: deployment %s has no workload", RuntimeType, in.Deployment.Metadata.Name)
	}
	client, err := a.newClient()
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes client: %w", err)
	}
	out := make(chan types.LogLine, 64)
	go func() {
		defer close(out)
		if err := client.logs(ctx, namespace, name, in, out); err != nil && ctx.Err() == nil {
			select {
			case out <- types.LogLine{Timestamp: time.Now().UTC(), Stream: "registry", Line: err.Error()}:
			case <-ctx.Done():
			}
		}
	}()
	return out, nil
}

func failedApplyResult(reason, message string, now time.Time) *types.ApplyResult {
	return &types.ApplyResult{Conditions: []v1alpha1.Condition{{
		Type:               "Ready",
		Status:             v1alpha1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	}}}
}
