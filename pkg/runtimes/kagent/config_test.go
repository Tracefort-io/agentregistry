package kagent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

func TestDecodeRuntimeConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        map[string]any
		wantErr       bool
		wantNamespace string
	}{
		{name: "empty", config: nil, wantNamespace: "kagent"},
		{name: "namespace", config: map[string]any{"namespace": "agents"}, wantNamespace: "agents"},
		{
			name:          "0.10 kagentUrl is accepted and ignored",
			config:        map[string]any{"kagentUrl": "http://kagent-controller.kagent.svc:8083", "namespace": "kagent"},
			wantNamespace: "kagent",
		},
		{name: "invalid namespace", config: map[string]any{"namespace": "Not_Valid"}, wantErr: true},
		{name: "auth is rejected", config: map[string]any{"auth": map[string]any{"secretRef": map[string]any{}}}, wantErr: true},
		{name: "auth is rejected case-insensitively", config: map[string]any{"Auth": map[string]any{}}, wantErr: true},
		{
			name:    "invalid label key",
			config:  map[string]any{"deployment": map[string]any{"labels": map[string]any{"bad key!": "x"}}},
			wantErr: true,
		},
		{
			name:    "invalid label value",
			config:  map[string]any{"deployment": map[string]any{"labels": map[string]any{"team": "not valid!"}}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := decodeRuntimeConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				require.Error(t, validateRuntimeConfigForAdmission(tt.config))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantNamespace, targetNamespace(cfg))
			assert.Equal(t, tt.wantNamespace, RuntimeNamespace(tt.config))
		})
	}
}

func TestDecodeDeployConfig(t *testing.T) {
	assert.NoError(t, decodeDeployConfig(nil))
	assert.NoError(t, decodeDeployConfig(map[string]any{}))
	assert.Error(t, decodeDeployConfig(map[string]any{"serviceAccountName": "sa"}))
}

func TestWorkloadName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"My Agent", "my-agent"},
		{"  io.github/server ", "io-github-server"},
		{"---", "resource"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, WorkloadName(tt.in), tt.in)
	}
}

func TestDeploymentWorkloadNameKeepsEstablishedRuntimeID(t *testing.T) {
	deployment := &types.DeploymentRecord{
		Deployment:   &v1alpha1.Deployment{Metadata: v1alpha1.ObjectMeta{Name: "d", Namespace: "default"}},
		InternalMeta: types.DeploymentInternalMeta{RuntimeID: "existing"},
	}
	assert.Equal(t, "existing", DeploymentWorkloadName(deployment))

	deployment.InternalMeta = types.DeploymentInternalMeta{}
	first := DeploymentWorkloadName(deployment)
	assert.Regexp(t, `^d-[0-9a-f]{12}$`, first)
	assert.Equal(t, first, DeploymentWorkloadName(deployment), "stable for the same Deployment")
}

func TestBuildRemoteMCPServerDescriptionFallsBackToName(t *testing.T) {
	input := mcpApplyInput()
	input.Target.(*v1alpha1.MCPServer).Spec.Description = ""
	server, err := buildRemoteMCPServer(input, runtimeConfig{})
	require.NoError(t, err)
	assert.Equal(t, "gh-mcp", server.Object["spec"].(map[string]any)["description"])
	assert.Equal(t, defaultRuntimeNamespace, server.GetNamespace())
}
