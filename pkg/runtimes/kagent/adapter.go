package kagent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

type adapter struct {
	newClient func() (kagentClient, error)
}

type Option func(*adapter)

// New returns the Kagent 1.x adapter. It reaches Kagent through the
// Kubernetes API with the registry's in-cluster ServiceAccount.
func New(options ...Option) types.DeploymentAdapter {
	return newAdapter(inClusterClient(), options...)
}

func newAdapter(newClient func() (kagentClient, error), options ...Option) *adapter {
	a := &adapter{newClient: newClient}
	for _, option := range options {
		option(a)
	}
	return a
}

var _ types.DeploymentAdapter = (*adapter)(nil)
var _ types.DeploymentDiscoverySource = (*adapter)(nil)

func (a *adapter) Type() string { return RuntimeType }

func (a *adapter) SupportedTargetKinds() []string {
	return []string{v1alpha1.KindAgent, v1alpha1.KindMCPServer}
}

func (a *adapter) Apply(ctx context.Context, input types.ApplyInput) (*types.ApplyResult, error) {
	now := time.Now().UTC()
	runtimeConfig, err := decodeRuntimeConfig(input.Runtime.Spec.Config)
	if err != nil {
		return FailedApplyResult(input.Target, "InvalidRuntimeConfig", err.Error(), now), nil
	}
	if err := decodeDeployConfig(input.Deployment.Spec.RuntimeConfig); err != nil {
		return FailedApplyResult(input.Target, "InvalidDeployConfig", err.Error(), now), nil
	}
	switch input.Target.(type) {
	case *v1alpha1.Agent:
		return FailedApplyResult(
			input.Target,
			"UnsupportedTarget",
			"deploying agents to Kagent 1.x is not supported yet",
			now,
		), nil
	case *v1alpha1.MCPServer:
		return a.applyMCPServer(ctx, input, runtimeConfig, now)
	default:
		return FailedApplyResult(
			input.Target,
			"UnsupportedTarget",
			fmt.Sprintf("target type %T is not supported", input.Target),
			now,
		), nil
	}
}

func (a *adapter) applyMCPServer(
	ctx context.Context,
	input types.ApplyInput,
	runtimeConfig runtimeConfig,
	now time.Time,
) (*types.ApplyResult, error) {
	server, err := buildRemoteMCPServer(input, runtimeConfig)
	if err != nil {
		if errors.Is(err, errUnsupported) {
			return FailedApplyResult(input.Target, "UnsupportedTarget", err.Error(), now), nil
		}
		return nil, err
	}
	client, err := a.newClient()
	if err != nil {
		return nil, fmt.Errorf("build kagent client: %w", err)
	}
	if err := client.ensureRemoteMCPServer(ctx, server); err != nil {
		return nil, err
	}
	url, _, _ := unstructured.NestedString(server.Object, "spec", "url")
	endpoint := &v1alpha1.Condition{
		Type:               mcpServerURLCondition,
		Status:             v1alpha1.ConditionTrue,
		Reason:             "RuntimeReady",
		Message:            url,
		LastTransitionTime: now,
	}
	return successfulApplyResult(server.GetName(), server.GetNamespace(), endpoint, now)
}

func (a *adapter) Remove(
	ctx context.Context,
	input types.RemoveInput,
) (*types.RemoveResult, error) {
	runtimeConfig, err := decodeRuntimeConfig(input.Runtime.Spec.Config)
	if err != nil {
		return nil, fmt.Errorf("kagent remove: %w", err)
	}
	now := time.Now().UTC()
	switch input.Deployment.Spec.TargetRef.Kind {
	case v1alpha1.KindAgent:
		// Kagent 1.x agents are never deployed by the registry.
		return &types.RemoveResult{Conditions: removedConditions(now)}, nil
	case v1alpha1.KindMCPServer:
	default:
		return nil, fmt.Errorf(
			"kagent remove: unsupported target kind %q",
			input.Deployment.Spec.TargetRef.Kind,
		)
	}

	name := DeploymentWorkloadName(input.Deployment)
	namespace := deploymentRuntimeNamespace(input.Deployment)
	if namespace == "" {
		namespace = targetNamespace(runtimeConfig)
	}
	client, err := a.newClient()
	if err != nil {
		return nil, fmt.Errorf("build kagent client: %w", err)
	}
	if err := client.deleteRemoteMCPServer(ctx, namespace, name); err != nil {
		return nil, fmt.Errorf("kagent remove %s/%s: %w", namespace, name, err)
	}
	conditions := append(removedConditions(now), v1alpha1.Condition{
		Type:               mcpServerURLCondition,
		Status:             v1alpha1.ConditionFalse,
		Reason:             "Removed",
		Message:            "Kagent MCP server removed",
		LastTransitionTime: now,
	})
	return &types.RemoveResult{Conditions: conditions}, nil
}

func (a *adapter) Logs(_ context.Context, in types.LogsInput) (<-chan types.LogLine, error) {
	if in.Deployment == nil {
		return nil, fmt.Errorf("kagent logs: deployment is required")
	}
	ch := make(chan types.LogLine, 1)
	if ready := in.Deployment.Status.GetCondition("Ready"); ready != nil &&
		ready.Status == v1alpha1.ConditionFalse && ready.Reason == "Failed" && ready.Message != "" {
		ch <- types.LogLine{Timestamp: ready.LastTransitionTime, Stream: "stdout", Line: ready.Message}
	}
	close(ch)
	return ch, nil
}
