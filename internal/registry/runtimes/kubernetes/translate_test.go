package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

const testDeploymentUID = "4b1c1e0e-3f2a-4c55-9d8e-2a7f6c1b9e10"

func agentInput(agentName, image string, env map[string]string) types.ApplyInput {
	return types.ApplyInput{
		Deployment: &types.DeploymentRecord{Deployment: &v1alpha1.Deployment{
			Metadata: v1alpha1.ObjectMeta{Name: "Loan Desk", Namespace: "default", UID: testDeploymentUID},
			Spec: v1alpha1.DeploymentSpec{
				TargetRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: agentName},
				Env:       env,
			},
		}},
		Target: &v1alpha1.Agent{
			Metadata: v1alpha1.ObjectMeta{Name: agentName, Namespace: "default"},
			Spec:     v1alpha1.AgentSpec{Source: &v1alpha1.AgentSource{Image: image}},
		},
		Runtime: &v1alpha1.Runtime{Spec: v1alpha1.RuntimeSpec{Type: RuntimeType, Config: validRuntimeConfig()}},
	}
}

func mustConfig(t *testing.T) runtimeConfig {
	t.Helper()
	cfg, err := decodeRuntimeConfig(validRuntimeConfig())
	require.NoError(t, err)
	return cfg
}

func envMap(vars []corev1.EnvVar) map[string]string {
	out := map[string]string{}
	for _, v := range vars {
		out[v.Name] = v.Value
	}
	return out
}

func TestBuildWorkload(t *testing.T) {
	two := int32(2)
	w, err := buildWorkload(agentInput("credit-checker", "registry.example/credit:1.0", map[string]string{"LOG_LEVEL": "debug"}),
		mustConfig(t), deployConfig{Replicas: &two})
	require.NoError(t, err)

	assert.Equal(t, "org-default", w.namespace)
	assert.Regexp(t, `^loan-desk-[0-9a-f]{12}$`, w.name)
	assert.Equal(t, "spiffe://tracefort.localhost/org/default/agent/credit-checker/deployment/"+testDeploymentUID+"/", w.actorSubject)

	pod := w.deployment.Spec.Template
	assert.Equal(t, "credit-checker", pod.Labels[agentLabel], "the org's ClusterSPIFFEID names the agent from this label")
	assert.Equal(t, testDeploymentUID, pod.Labels[deploymentUIDLabel], "and makes the ID unique with this one")
	assert.Equal(t, w.name, pod.Labels[workloadLabel])
	assert.Equal(t, map[string]string{workloadLabel: w.name}, w.deployment.Spec.Selector.MatchLabels)
	assert.Equal(t, two, *w.deployment.Spec.Replicas)

	spec := pod.Spec
	require.False(t, *spec.AutomountServiceAccountToken)
	require.False(t, *w.serviceAccount.AutomountServiceAccountToken)
	assert.Equal(t, w.name, spec.ServiceAccountName)
	require.True(t, *spec.SecurityContext.RunAsNonRoot)
	assert.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, spec.SecurityContext.SeccompProfile.Type)
	container := spec.Containers[0]
	assert.Equal(t, "registry.example/credit:1.0", container.Image)
	require.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
	assert.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)

	require.Len(t, spec.Volumes, 1)
	assert.Equal(t, "csi.spiffe.io", spec.Volumes[0].CSI.Driver)
	require.True(t, *spec.Volumes[0].CSI.ReadOnly)
	assert.Equal(t, []corev1.VolumeMount{{Name: spiffeVolume, MountPath: spiffeMountPath, ReadOnly: true}}, container.VolumeMounts)

	env := envMap(container.Env)
	assert.Equal(t, "unix:///spiffe-workload-api/spire-agent.sock", env[envSPIFFESocket])
	assert.Equal(t, "https://tracefort-agentgateway.tracefort-control-plane.svc:8443", env[envGatewayURL])
	assert.Equal(t, "spiffe://tracefort.localhost/gateway/tracefort-control-plane/tracefort-agentgateway", env[envGatewaySPIFFEID])
	assert.Equal(t, "agentgateway", env[envGatewayAudience], "the default audience")
	assert.Equal(t, "openbao", env[envOpenBaoAudience])
	assert.Equal(t, "x-openbao-svid", env[envOpenBaoSVIDHeader])
	assert.Equal(t, "default", env[envOrg])
	assert.Equal(t, "credit-checker", env[envAgent])
	assert.Equal(t, "debug", env["LOG_LEVEL"])
	for name := range env {
		assert.NotContains(t, []string{"OPENBAO_TOKEN", "VAULT_TOKEN"}, name)
	}
}

func TestBuildWorkloadCommandArgsAndUser(t *testing.T) {
	user := int64(65532)
	w, err := buildWorkload(agentInput("credit-checker", "img", nil), mustConfig(t),
		deployConfig{Command: []string{"/opt/agent"}, Args: []string{"serve", "--port", "8080"}, RunAsUser: &user})
	require.NoError(t, err)
	spec := w.deployment.Spec.Template.Spec
	assert.Equal(t, []string{"/opt/agent"}, spec.Containers[0].Command)
	assert.Equal(t, []string{"serve", "--port", "8080"}, spec.Containers[0].Args)
	require.NotNil(t, spec.SecurityContext.RunAsUser)
	assert.Equal(t, user, *spec.SecurityContext.RunAsUser)
	require.True(t, *spec.SecurityContext.RunAsNonRoot, "still refused as root whatever the image says")

	w, err = buildWorkload(agentInput("credit-checker", "img", nil), mustConfig(t), deployConfig{})
	require.NoError(t, err)
	spec = w.deployment.Spec.Template.Spec
	assert.Nil(t, spec.Containers[0].Command, "the image's entrypoint by default")
	assert.Nil(t, spec.Containers[0].Args)
	assert.Nil(t, spec.SecurityContext.RunAsUser, "the image's user by default")
}

func TestBuildWorkloadNetworkPolicy(t *testing.T) {
	w, err := buildWorkload(agentInput("credit-checker", "img", nil), mustConfig(t), deployConfig{})
	require.NoError(t, err)
	policy := w.networkPolicy.Spec

	assert.Equal(t, map[string]string{workloadLabel: w.name}, policy.PodSelector.MatchLabels)
	assert.ElementsMatch(t, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, policy.PolicyTypes)
	assert.Empty(t, policy.Ingress, "no ingress")
	require.Len(t, policy.Egress, 2, "the gateway and DNS only")

	gateway := policy.Egress[0].To[0]
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "tracefort-control-plane"}, gateway.NamespaceSelector.MatchLabels)
	assert.Equal(t, map[string]string{"gateway.networking.k8s.io/gateway-name": "tracefort-agentgateway"}, gateway.PodSelector.MatchLabels)

	dns := policy.Egress[1]
	assert.Equal(t, map[string]string{"k8s-app": "kube-dns"}, dns.To[0].PodSelector.MatchLabels)
	require.Len(t, dns.Ports, 2)
	assert.Equal(t, int32(53), dns.Ports[0].Port.IntVal)
}

func TestBuildWorkloadRefusals(t *testing.T) {
	cfg := mustConfig(t)
	tests := []struct {
		name    string
		in      types.ApplyInput
		wantErr string
	}{
		{"agent name not a DNS label", agentInput("Credit_Checker", "img", nil), "must be a DNS label"},
		{"no image", agentInput("credit-checker", " ", nil), "no container image"},
		{"reserved env", agentInput("credit-checker", "img", map[string]string{envGatewaySPIFFEID: "spiffe://evil/x"}), "set by the runtime"},
		{"no Deployment UID", func() types.ApplyInput {
			in := agentInput("credit-checker", "img", nil)
			in.Deployment.Metadata.UID = ""
			return in
		}(), "would not be unique"},
		{"MCP server target", types.ApplyInput{
			Deployment: agentInput("x", "img", nil).Deployment,
			Target:     &v1alpha1.MCPServer{},
			Runtime:    agentInput("x", "img", nil).Runtime,
		}, "want an Agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildWorkload(tt.in, cfg, deployConfig{})
			require.ErrorIs(t, err, errInvalidTarget)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestWorkloadNameIsStableAndDistinct(t *testing.T) {
	record := func(name string) *types.DeploymentRecord {
		return &types.DeploymentRecord{Deployment: &v1alpha1.Deployment{Metadata: v1alpha1.ObjectMeta{Name: name, Namespace: "default"}}}
	}
	first, second := workloadName(record("loan desk")), workloadName(record("loan desk"))
	assert.Equal(t, first, second, "the same Deployment always gets the same name")
	assert.NotEqual(t, workloadName(record("loan desk")), workloadName(record("loan-desk")),
		"names that map to the same label still get different objects")

	applied := record("loan desk")
	applied.InternalMeta.RuntimeName = "kept-name"
	assert.Equal(t, "kept-name", workloadName(applied), "an applied workload keeps its name")
}
