package kagent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

func newFakeDynamic(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			agentsResource:           "AgentList",
			remoteMCPServersResource: "RemoteMCPServerList",
		},
		objects...,
	)
}

func testAdapter(dyn *dynamicfake.FakeDynamicClient) *adapter {
	client := newDynamicClient(dyn)
	return newAdapter(func() (kagentClient, error) { return client, nil })
}

func kagentObject(kind, namespace, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{}}}
	obj.SetAPIVersion(kagentGroup + "/" + kagentVersion)
	obj.SetKind(kind)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}

func runtimeWithConfig(config map[string]any) *v1alpha1.Runtime {
	return &v1alpha1.Runtime{Spec: v1alpha1.RuntimeSpec{Type: RuntimeType, Config: config}}
}

func mcpApplyInput() types.ApplyInput {
	return types.ApplyInput{
		Deployment: &types.DeploymentRecord{Deployment: &v1alpha1.Deployment{
			Metadata: v1alpha1.ObjectMeta{Name: "my-deploy", Namespace: "default"},
			Spec: v1alpha1.DeploymentSpec{
				TargetRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindMCPServer, Name: "gh-mcp"},
			},
		}},
		Target: &v1alpha1.MCPServer{
			Metadata: v1alpha1.ObjectMeta{Name: "gh-mcp", Namespace: "default"},
			Spec: v1alpha1.MCPServerSpec{
				Description: "GitHub tools",
				Remote: &v1alpha1.MCPRemote{
					Type: "streamable-http",
					URL:  "https://mcp.example.com/mcp",
				},
			},
		},
		Runtime: runtimeWithConfig(map[string]any{"namespace": "kagent"}),
	}
}

func agentApplyInput() types.ApplyInput {
	return types.ApplyInput{
		Deployment: &types.DeploymentRecord{Deployment: &v1alpha1.Deployment{
			Metadata: v1alpha1.ObjectMeta{Name: "agent-deploy", Namespace: "default"},
			Spec: v1alpha1.DeploymentSpec{
				TargetRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "my-agent"},
			},
		}},
		Target: &v1alpha1.Agent{
			Metadata: v1alpha1.ObjectMeta{Name: "my-agent", Namespace: "default"},
			Spec:     v1alpha1.AgentSpec{Source: &v1alpha1.AgentSource{Image: "example/agent:1.0.0"}},
		},
		Runtime: runtimeWithConfig(nil),
	}
}

func findCondition(conditions []v1alpha1.Condition, conditionType string) *v1alpha1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func getRemoteMCPServer(t *testing.T, dyn *dynamicfake.FakeDynamicClient, namespace, name string) *unstructured.Unstructured {
	t.Helper()
	obj, err := dyn.Resource(remoteMCPServersResource).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	return obj
}

func TestApplyMCPServerCreatesRemoteMCPServer(t *testing.T) {
	dyn := newFakeDynamic()
	input := mcpApplyInput()

	result, err := testAdapter(dyn).Apply(context.Background(), input)
	require.NoError(t, err)

	name := DeploymentWorkloadName(input.Deployment)
	server := getRemoteMCPServer(t, dyn, "kagent", name)
	url, _, _ := unstructured.NestedString(server.Object, "spec", "url")
	assert.Equal(t, "https://mcp.example.com/mcp", url)
	assert.Equal(t, managedByValue, server.GetLabels()[managedByLabel])

	assert.Equal(t, name, result.InternalMeta.RuntimeID)
	assert.Equal(t, "kagent", result.InternalMeta.RuntimeNamespace)
	assert.Equal(t, "https://mcp.example.com/mcp", result.Runtime.Endpoint)
	assert.Equal(t, v1alpha1.ConditionTrue, findCondition(result.Conditions, "Ready").Status)
	endpoint := findCondition(result.Conditions, mcpServerURLCondition)
	require.NotNil(t, endpoint)
	assert.Equal(t, v1alpha1.ConditionTrue, endpoint.Status)
	assert.Equal(t, "https://mcp.example.com/mcp", endpoint.Message)
}

func TestApplyMCPServerUpdatesExisting(t *testing.T) {
	dyn := newFakeDynamic()
	a := testAdapter(dyn)
	input := mcpApplyInput()
	_, err := a.Apply(context.Background(), input)
	require.NoError(t, err)

	input.Target.(*v1alpha1.MCPServer).Spec.Remote.URL = "https://mcp.example.com/v2/mcp"
	input.Runtime = runtimeWithConfig(map[string]any{
		"namespace":  "kagent",
		"deployment": map[string]any{"labels": map[string]any{"team": "platform"}},
	})
	_, err = a.Apply(context.Background(), input)
	require.NoError(t, err)

	server := getRemoteMCPServer(t, dyn, "kagent", DeploymentWorkloadName(input.Deployment))
	url, _, _ := unstructured.NestedString(server.Object, "spec", "url")
	assert.Equal(t, "https://mcp.example.com/v2/mcp", url)
	assert.Equal(t, "platform", server.GetLabels()["team"])
}

func TestApplyRejections(t *testing.T) {
	tests := []struct {
		name       string
		input      func() types.ApplyInput
		wantReason string
	}{
		{
			name:       "agent",
			input:      agentApplyInput,
			wantReason: "UnsupportedTarget",
		},
		{
			name: "package-based MCP server",
			input: func() types.ApplyInput {
				in := mcpApplyInput()
				in.Target.(*v1alpha1.MCPServer).Spec.Remote = nil
				return in
			},
			wantReason: "UnsupportedTarget",
		},
		{
			name: "deployment runtimeConfig",
			input: func() types.ApplyInput {
				in := mcpApplyInput()
				in.Deployment.Spec.RuntimeConfig = map[string]any{"secretRefs": []any{"x"}}
				return in
			},
			wantReason: "InvalidDeployConfig",
		},
		{
			name: "runtime auth",
			input: func() types.ApplyInput {
				in := mcpApplyInput()
				in.Runtime = runtimeWithConfig(map[string]any{"auth": map[string]any{}})
				return in
			},
			wantReason: "InvalidRuntimeConfig",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dyn := newFakeDynamic()
			result, err := testAdapter(dyn).Apply(context.Background(), tt.input())
			require.NoError(t, err)
			ready := findCondition(result.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, v1alpha1.ConditionFalse, ready.Status)
			assert.Equal(t, "Failed", ready.Reason)
			assert.Empty(t, dyn.Actions(), "a rejected apply must not touch the cluster")
		})
	}
}

func TestRemoveMCPServerDeletesRemoteMCPServer(t *testing.T) {
	dyn := newFakeDynamic()
	a := testAdapter(dyn)
	input := mcpApplyInput()
	_, err := a.Apply(context.Background(), input)
	require.NoError(t, err)

	removeInput := types.RemoveInput{Deployment: input.Deployment, Runtime: input.Runtime}
	result, err := a.Remove(context.Background(), removeInput)
	require.NoError(t, err)
	assert.Equal(t, "Removed", findCondition(result.Conditions, "Ready").Reason)
	assert.Equal(t, v1alpha1.ConditionFalse, findCondition(result.Conditions, mcpServerURLCondition).Status)

	_, err = dyn.Resource(remoteMCPServersResource).Namespace("kagent").
		Get(context.Background(), DeploymentWorkloadName(input.Deployment), metav1.GetOptions{})
	require.Error(t, err)

	// Removing again tolerates the missing resource.
	_, err = a.Remove(context.Background(), removeInput)
	require.NoError(t, err)
}

func TestRemoveAgentDoesNotTouchCluster(t *testing.T) {
	dyn := newFakeDynamic()
	input := agentApplyInput()
	result, err := testAdapter(dyn).Remove(context.Background(), types.RemoveInput{
		Deployment: input.Deployment,
		Runtime:    input.Runtime,
	})
	require.NoError(t, err)
	assert.Equal(t, "Removed", findCondition(result.Conditions, "Ready").Reason)
	assert.Empty(t, dyn.Actions())
}

func TestDiscoverListsAgentsAndRemoteMCPServersInNamespace(t *testing.T) {
	dyn := newFakeDynamic(
		kagentObject("Agent", "kagent", "k8s-agent"),
		kagentObject("Agent", "kagent", "helm-agent"),
		kagentObject("Agent", "other", "elsewhere"),
		kagentObject(kindRemoteMCPServer, "kagent", "kagent-tool-server"),
	)
	results, err := testAdapter(dyn).Discover(context.Background(), types.DiscoverInput{
		Runtime: runtimeWithConfig(map[string]any{"kagentUrl": "http://kagent-controller.kagent.svc:8083"}),
	})
	require.NoError(t, err)

	got := map[string]string{}
	for _, r := range results {
		got[r.Name] = r.TargetKind
		assert.Equal(t, r.Name, r.InternalMeta.RuntimeID)
		assert.Equal(t, "kagent", r.InternalMeta.RuntimeNamespace)
	}
	assert.Equal(t, map[string]string{
		"k8s-agent":          v1alpha1.KindAgent,
		"helm-agent":         v1alpha1.KindAgent,
		"kagent-tool-server": v1alpha1.KindMCPServer,
	}, got)
}

func TestApplyAndDiscoverUseSameRemoteID(t *testing.T) {
	dyn := newFakeDynamic()
	a := testAdapter(dyn)
	input := mcpApplyInput()
	result, err := a.Apply(context.Background(), input)
	require.NoError(t, err)

	discovered, err := a.Discover(context.Background(), types.DiscoverInput{Runtime: input.Runtime})
	require.NoError(t, err)
	require.Len(t, discovered, 1)
	assert.Equal(t, result.InternalMeta.RuntimeID, discovered[0].InternalMeta.RuntimeID)
}
