package kubernetes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

func testAdapter(clientset *fake.Clientset) *adapter {
	client := newClientsetClient(clientset)
	return &adapter{newClient: func() (workloadClient, error) { return client, nil }}
}

func applied(t *testing.T, a *adapter, in types.ApplyInput) *types.DeploymentRecord {
	t.Helper()
	result, err := a.Apply(context.Background(), in)
	require.NoError(t, err)
	record := in.Deployment
	record.InternalMeta = *result.InternalMeta
	return record
}

func TestApplyCreatesWorkload(t *testing.T) {
	clientset := fake.NewClientset()
	a := testAdapter(clientset)
	result, err := a.Apply(context.Background(), agentInput("credit-checker", "img", nil))
	require.NoError(t, err)

	meta := result.InternalMeta
	require.NotNil(t, meta)
	assert.Equal(t, "org-default", meta.RuntimeNamespace)
	assert.Equal(t, "spiffe://tracefort.localhost/org/default/agent/credit-checker/deployment/"+testDeploymentUID+"/", meta.ActorSubject)
	assert.Equal(t, v1alpha1.AgentProtocolA2A, meta.AppProtocol)
	require.Len(t, result.Conditions, 1)
	assert.Equal(t, v1alpha1.ConditionFalse, result.Conditions[0].Status)
	assert.Equal(t, "Progressing", result.Conditions[0].Reason)

	ctx := context.Background()
	_, err = clientset.NetworkingV1().NetworkPolicies("org-default").Get(ctx, meta.RuntimeName, metav1.GetOptions{})
	require.NoError(t, err)
	_, err = clientset.CoreV1().ServiceAccounts("org-default").Get(ctx, meta.RuntimeName, metav1.GetOptions{})
	require.NoError(t, err)
	deployment, err := clientset.AppsV1().Deployments("org-default").Get(ctx, meta.RuntimeName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "credit-checker", deployment.Spec.Template.Labels[agentLabel])
}

func TestPlanIdentityMatchesApply(t *testing.T) {
	a := testAdapter(fake.NewClientset())
	in := agentInput("credit-checker", "img", nil)

	plan, err := a.PlanIdentity(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, plan)
	result, err := a.Apply(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, result.InternalMeta.ActorSubject, plan.SPIFFEIDPrefix)
	assert.Equal(t, result.InternalMeta.RuntimeNamespace, plan.WorkloadNamespace)
	assert.Equal(t, result.InternalMeta.RuntimeName, plan.WorkloadName)

	refused := agentInput("Bad_Name", "img", nil)
	plan, err = a.PlanIdentity(context.Background(), refused)
	require.NoError(t, err)
	assert.Nil(t, plan, "input Apply refuses gives no identity")
}

func TestApplyUpdatesExistingWorkload(t *testing.T) {
	clientset := fake.NewClientset()
	a := testAdapter(clientset)
	record := applied(t, a, agentInput("credit-checker", "img:1", nil))

	in := agentInput("credit-checker", "img:2", nil)
	in.Deployment = record
	_, err := a.Apply(context.Background(), in)
	require.NoError(t, err)

	deployment, err := clientset.AppsV1().Deployments("org-default").Get(context.Background(), record.InternalMeta.RuntimeName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "img:2", deployment.Spec.Template.Spec.Containers[0].Image)
}

func TestApplyRefusesInvalidInputWithoutCallingKubernetes(t *testing.T) {
	clientset := fake.NewClientset()
	a := testAdapter(clientset)

	tests := []struct {
		name       string
		mutate     func(in *types.ApplyInput)
		wantReason string
	}{
		{"runtime config", func(in *types.ApplyInput) { in.Runtime.Spec.Config = map[string]any{} }, "InvalidRuntimeConfig"},
		{"deploy config", func(in *types.ApplyInput) { in.Deployment.Spec.RuntimeConfig = map[string]any{"replicas": 0} }, "InvalidDeployConfig"},
		{"agent name", func(in *types.ApplyInput) { in.Target.(*v1alpha1.Agent).Metadata.Name = "Bad_Name" }, "InvalidTarget"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := agentInput("credit-checker", "img", nil)
			tt.mutate(&in)
			result, err := a.Apply(context.Background(), in)
			require.NoError(t, err)
			assert.Nil(t, result.InternalMeta, "nothing was created")
			assert.Equal(t, tt.wantReason, result.Conditions[0].Reason)
		})
	}
	require.Empty(t, clientset.Actions())
}

func TestReadyCondition(t *testing.T) {
	two := int32(2)
	deployment := func(status appsv1.DeploymentStatus, generation int64) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Generation: generation},
			Spec:       appsv1.DeploymentSpec{Replicas: &two},
			Status:     status,
		}
	}
	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		wantStatus v1alpha1.ConditionStatus
		wantReason string
	}{
		{"all available", deployment(appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2}, 1),
			v1alpha1.ConditionTrue, "Available"},
		{"rolling out", deployment(appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 2, UpdatedReplicas: 1, AvailableReplicas: 2}, 1),
			v1alpha1.ConditionFalse, "Progressing"},
		{"new generation not yet observed", deployment(appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2}, 2),
			v1alpha1.ConditionFalse, "Progressing"},
		{"progress deadline exceeded", deployment(appsv1.DeploymentStatus{ObservedGeneration: 1, Conditions: []appsv1.DeploymentCondition{{
			Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: "image pull"}}}, 1),
			v1alpha1.ConditionFalse, "ProgressDeadlineExceeded"},
		{"replica failure", deployment(appsv1.DeploymentStatus{ObservedGeneration: 1, Conditions: []appsv1.DeploymentCondition{{
			Type: appsv1.DeploymentReplicaFailure, Status: corev1.ConditionTrue, Message: "forbidden"}}}, 1),
			v1alpha1.ConditionFalse, "ReplicaFailure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readyCondition(tt.deployment)
			assert.Equal(t, "Ready", got.Type)
			assert.Equal(t, tt.wantStatus, got.Status)
			assert.Equal(t, tt.wantReason, got.Reason)
		})
	}
}

func TestObserveStatus(t *testing.T) {
	clientset := fake.NewClientset()
	a := testAdapter(clientset)
	record := applied(t, a, agentInput("credit-checker", "img", nil))
	ctx := context.Background()

	result, err := a.ObserveStatus(ctx, types.ObserveInput{Deployment: record})
	require.NoError(t, err)
	assert.Equal(t, "Progressing", result.Conditions[0].Reason)

	deployments := clientset.AppsV1().Deployments("org-default")
	d, err := deployments.Get(ctx, record.InternalMeta.RuntimeName, metav1.GetOptions{})
	require.NoError(t, err)
	d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}
	_, err = deployments.UpdateStatus(ctx, d, metav1.UpdateOptions{})
	require.NoError(t, err)
	result, err = a.ObserveStatus(ctx, types.ObserveInput{Deployment: record})
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.ConditionTrue, result.Conditions[0].Status)

	require.NoError(t, deployments.Delete(ctx, record.InternalMeta.RuntimeName, metav1.DeleteOptions{}))
	result, err = a.ObserveStatus(ctx, types.ObserveInput{Deployment: record})
	require.NoError(t, err)
	assert.Equal(t, "NotFound", result.Conditions[0].Reason)

	result, err = a.ObserveStatus(ctx, types.ObserveInput{Deployment: agentInput("x", "img", nil).Deployment})
	require.NoError(t, err)
	assert.Nil(t, result, "a Deployment whose Apply created nothing is left alone")
}

func TestRemoveDeletesWorkloadAndWaitsForPods(t *testing.T) {
	clientset := fake.NewClientset()
	a := testAdapter(clientset)
	record := applied(t, a, agentInput("credit-checker", "img", nil))
	ctx := context.Background()
	name := record.InternalMeta.RuntimeName

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-abc", Namespace: "org-default", Labels: map[string]string{workloadLabel: name}}}
	_, err := clientset.CoreV1().Pods("org-default").Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = a.Remove(ctx, types.RemoveInput{Deployment: record})
	require.ErrorContains(t, err, "still terminating", "Remove keeps failing until the pods are gone")
	_, err = clientset.NetworkingV1().NetworkPolicies("org-default").Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err, "the NetworkPolicy stays while pods remain")

	require.NoError(t, clientset.CoreV1().Pods("org-default").Delete(ctx, pod.Name, metav1.DeleteOptions{}))
	result, err := a.Remove(ctx, types.RemoveInput{Deployment: record})
	require.NoError(t, err)
	assert.Equal(t, "Removed", result.Conditions[0].Reason)
	_, err = clientset.NetworkingV1().NetworkPolicies("org-default").Get(ctx, name, metav1.GetOptions{})
	require.Error(t, err)
	_, err = clientset.AppsV1().Deployments("org-default").Get(ctx, name, metav1.GetOptions{})
	require.Error(t, err)

	result, err = a.Remove(ctx, types.RemoveInput{Deployment: record})
	require.NoError(t, err, "Remove is idempotent")
	assert.Equal(t, "Removed", result.Conditions[0].Reason)
}

func TestLogs(t *testing.T) {
	clientset := fake.NewClientset()
	a := testAdapter(clientset)
	record := applied(t, a, agentInput("credit-checker", "img", nil))
	ctx := context.Background()
	name := record.InternalMeta.RuntimeName
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-abc", Namespace: "org-default", Labels: map[string]string{workloadLabel: name}}}
	_, err := clientset.CoreV1().Pods("org-default").Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err)

	ch, err := a.Logs(ctx, types.LogsInput{Deployment: record})
	require.NoError(t, err)
	var lines []types.LogLine
	for line := range ch {
		lines = append(lines, line)
	}
	require.NotEmpty(t, lines)
	assert.Equal(t, pod.Name, lines[0].Stream)

	_, err = a.Logs(ctx, types.LogsInput{Deployment: agentInput("x", "img", nil).Deployment})
	require.ErrorContains(t, err, "has no workload")
}
