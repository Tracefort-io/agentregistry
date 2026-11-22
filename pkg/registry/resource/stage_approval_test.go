package resource

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	arv0 "github.com/agentregistry-dev/agentregistry/pkg/api/v0"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// holdStager holds every refused write when holds is set.
type holdStager struct {
	holds  bool
	staged []types.ApprovalStageInput
}

func (s *holdStager) Holds(context.Context, string, error) bool { return s.holds }

func (s *holdStager) Stage(_ context.Context, in types.ApprovalStageInput) (string, bool, error) {
	s.staged = append(s.staged, in)
	return "arq_1", true, nil
}

var errNeedsApproval = errors.New("approval required")

func decodeObject(t *testing.T, doc string) v1alpha1.Object {
	t.Helper()
	v, err := v1alpha1.Default.Decode([]byte(doc))
	require.NoError(t, err)
	obj, ok := v.(v1alpha1.Object)
	require.True(t, ok, "decoded %T", v)
	return obj
}

const weatherServer = `apiVersion: ar.dev/v1alpha1
kind: MCPServer
metadata:
  namespace: default
  name: %s
  tag: "1.0.0"
  labels:
    team: platform
spec:
  description: Weather tools.
  source:
    package:
      origin:
        type: oci
        identifier: ghcr.io/example/weather-mcp:1.0.0
        oci:
          serverName: io.github.example/weather
      transport:
        type: http
        port: 8080
`

func mcpServer(t *testing.T, name string) v1alpha1.Object {
	t.Helper()
	return decodeObject(t, fmt.Sprintf(weatherServer, name))
}

func TestStageForApprovalChecksBeforeHolding(t *testing.T) {
	errUnpublished := errors.New("OCI image does not exist in the registry")
	tests := []struct {
		name       string
		holds      bool
		dryRun     bool
		objName    string
		registries v1alpha1.RegistryValidatorFunc
		wantFinal  bool
		wantStatus string
		wantError  string
		wantStaged bool
	}{
		{name: "a refusal that is not held stays a refusal", holds: false, objName: "weather", wantFinal: false},
		{name: "a dry run is never held", holds: true, dryRun: true, objName: "weather", wantFinal: false},
		{name: "a valid document is held", holds: true, objName: "weather",
			wantFinal: true, wantStatus: arv0.ApplyStatusPendingApproval, wantStaged: true},
		{name: "an invalid document is refused, not held", holds: true, objName: "Not_A_DNS_Name",
			wantFinal: true, wantStatus: arv0.ApplyStatusFailed, wantError: "validation:"},
		{name: "a package its registry refuses is refused, not held", holds: true, objName: "weather",
			registries: func(context.Context, v1alpha1.MCPPackageOrigin, string) error { return errUnpublished },
			wantFinal:  true, wantStatus: arv0.ApplyStatusFailed, wantError: "registries:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &holdStager{holds: tt.holds}
			cfg := ApplyConfig{Approvals: st, RegistryValidator: tt.registries}
			obj := mcpServer(t, tt.objName)
			res := arv0.ApplyResult{Kind: v1alpha1.KindMCPServer, Namespace: "default", Name: tt.objName}

			got, final := stageForApproval(context.Background(), cfg, nil, res, &applyError{Stage: stageAuth, Err: errNeedsApproval},
				"apply", *obj.GetMetadata(), obj, tt.dryRun)

			assert.Equal(t, tt.wantFinal, final)
			if !tt.wantFinal {
				assert.Empty(t, st.staged)
				return
			}
			assert.Equal(t, tt.wantStatus, got.Status)
			assert.Contains(t, got.Error, tt.wantError)
			if tt.wantStaged {
				require.Len(t, st.staged, 1)
				assert.Equal(t, "arq_1", got.ApprovalRequest)
				assert.Same(t, obj, st.staged[0].Object)
			} else {
				assert.Empty(t, st.staged, "nothing is sent to approvers")
			}
		})
	}
}

func TestStageForApprovalHoldsTheDocumentAsSubmitted(t *testing.T) {
	// Validation canonicalizes a Runtime's spec.type; the held document must
	// stay the one whose hash the denial is bound to.
	v1alpha1.KnownRuntimeTypes["TestRuntime"] = struct{}{}
	t.Cleanup(func() { delete(v1alpha1.KnownRuntimeTypes, "TestRuntime") })
	obj := decodeObject(t, `apiVersion: ar.dev/v1alpha1
kind: Runtime
metadata:
  namespace: default
  name: lab
spec:
  type: testruntime
`)
	st := &holdStager{holds: true}
	res := arv0.ApplyResult{Kind: v1alpha1.KindRuntime, Namespace: "default", Name: "lab"}

	got, final := stageForApproval(context.Background(), ApplyConfig{Approvals: st}, nil, res,
		&applyError{Stage: stageAuth, Err: errNeedsApproval}, "apply", *obj.GetMetadata(), obj, false)

	require.True(t, final)
	assert.Equal(t, arv0.ApplyStatusPendingApproval, got.Status, got.Error)
	require.Len(t, st.staged, 1)
	assert.Equal(t, "testruntime", st.staged[0].Object.(*v1alpha1.Runtime).Spec.Type)
}

func TestStageForApprovalHoldsDeletesWithoutChecks(t *testing.T) {
	st := &holdStager{holds: true}
	res := arv0.ApplyResult{Kind: v1alpha1.KindMCPServer, Namespace: "default", Name: "Not_A_DNS_Name"}
	meta := v1alpha1.ObjectMeta{Namespace: "default", Name: "Not_A_DNS_Name"}

	got, final := stageForApproval(context.Background(), ApplyConfig{Approvals: st}, nil, res,
		&applyError{Stage: stageAuth, Err: errNeedsApproval}, "delete", meta, nil, false)

	require.True(t, final)
	assert.Equal(t, arv0.ApplyStatusPendingApproval, got.Status)
	require.Len(t, st.staged, 1)
	assert.Nil(t, st.staged[0].Object)
}

func TestCopyObject(t *testing.T) {
	obj := mcpServer(t, "weather")
	cp, err := copyObject(obj)
	require.NoError(t, err)
	require.NotSame(t, obj, cp)
	assert.Equal(t, obj, cp)

	cp.(*v1alpha1.MCPServer).Spec.Description = "changed"
	cp.GetMetadata().Labels["team"] = "changed"
	assert.Equal(t, "Weather tools.", obj.(*v1alpha1.MCPServer).Spec.Description, "the copy shares nothing")
	assert.Equal(t, "platform", obj.GetMetadata().Labels["team"])
}

func TestCopyObjectKeepsTheDefaultNamespaceAndGeneration(t *testing.T) {
	// The wire form drops both; the copy must not.
	obj := mcpServer(t, "weather")
	meta := *obj.GetMetadata()
	meta.Generation = 7
	obj.SetMetadata(meta)

	cp, err := copyObject(obj)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.DefaultNamespace, cp.GetMetadata().Namespace)
	assert.Equal(t, int64(7), cp.GetMetadata().Generation)
}
