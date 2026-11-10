package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

func TestCheck_Mapping(t *testing.T) {
	tests := []struct {
		verb       auth.PermissionAction
		typ        auth.PermissionArtifactType
		name       string
		wantAction string
		wantType   string
	}{
		{auth.PermissionActionRead, auth.PermissionArtifactTypeAgent, "team/a", "read", "agent"},
		{auth.PermissionActionPublish, auth.PermissionArtifactTypeSkill, "team/s", "apply", "skill"},
		{auth.PermissionActionEdit, auth.PermissionArtifactTypePrompt, "team/p", "apply", "prompt"},
		{auth.PermissionActionDelete, auth.PermissionArtifactTypeServer, "team/m", "delete", "mcpserver"},
		{auth.PermissionActionDeploy, auth.PermissionArtifactTypeRuntime, "team/r", "deploy", "runtime"},
	}
	for _, tt := range tests {
		t.Run(string(tt.verb)+"/"+string(tt.typ), func(t *testing.T) {
			pdp := newMockPDP(nil)
			p := newPEP(t, pdp, nil)
			require.NoError(t, p.Check(context.Background(), userSession{p: alice()}, tt.verb, auth.Resource{Name: tt.name, Type: tt.typ}))
			require.Len(t, pdp.evals, 1)
			assert.Equal(t, tt.wantAction, pdp.evals[0].Action.Name)
			assert.Equal(t, tt.wantType, pdp.evals[0].Resource.Type)
			assert.Equal(t, tt.name, pdp.evals[0].Resource.ID)
		})
	}
}

func TestCheck_Outcomes(t *testing.T) {
	deny := func(authzen.EvaluationRequest) bool { return false }
	res := auth.Resource{Name: "team/a", Type: auth.PermissionArtifactTypeAgent}
	tests := []struct {
		name       string
		session    auth.Session
		verb       auth.PermissionAction
		decide     func(authzen.EvaluationRequest) bool
		pdpErr     error
		wantStatus int
		wantIs     error
	}{
		{name: "permit", session: userSession{p: alice()}, verb: auth.PermissionActionRead},
		{name: "deny is 403", session: userSession{p: alice()}, verb: auth.PermissionActionRead, decide: deny, wantStatus: 403, wantIs: auth.ErrForbidden},
		{name: "pdp failure is 503", session: userSession{p: alice()}, verb: auth.PermissionActionRead, pdpErr: errPDPDown, wantStatus: 503, wantIs: auth.ErrForbidden},
		{name: "unknown action", session: userSession{p: alice()}, verb: "frobnicate", wantStatus: 403, wantIs: auth.ErrForbidden},
		{name: "nil session", session: nil, verb: auth.PermissionActionRead, wantStatus: 401, wantIs: auth.ErrUnauthenticated},
		{name: "system", session: &auth.SystemSession{}, verb: auth.PermissionActionDelete, decide: deny},
		{name: "public denied", session: &auth.PublicSession{}, verb: auth.PermissionActionRead, decide: deny, wantStatus: 403, wantIs: auth.ErrForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(tt.decide)
			pdp.err = tt.pdpErr
			err := newPEP(t, pdp, nil).Check(context.Background(), tt.session, tt.verb, res)
			if tt.wantStatus == 0 {
				require.NoError(t, err)
				return
			}
			assert.Equal(t, tt.wantStatus, StatusOf(err))
			assert.ErrorIs(t, err, tt.wantIs)
		})
	}
}

func TestIsRegistryAdmin(t *testing.T) {
	tests := []struct {
		name    string
		session auth.Session
		permit  bool
		pdpErr  error
		want    bool
		calls   int
	}{
		{name: "permit", session: userSession{p: alice()}, permit: true, want: true, calls: 1},
		{name: "deny", session: userSession{p: alice()}, permit: false, want: false, calls: 1},
		{name: "error fails closed", session: userSession{p: alice()}, permit: true, pdpErr: errPDPDown, want: false, calls: 1},
		{name: "system", session: &auth.SystemSession{}, want: true},
		{name: "nil session", session: nil, permit: true, want: false},
		{name: "unauthenticated principal", session: userSession{}, permit: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(func(authzen.EvaluationRequest) bool { return tt.permit })
			pdp.err = tt.pdpErr
			got := newPEP(t, pdp, nil).IsRegistryAdmin(context.Background(), tt.session)
			assert.Equal(t, tt.want, got)
			require.Len(t, pdp.evals, tt.calls)
			if tt.calls > 0 {
				assert.Equal(t, "admin", pdp.evals[0].Action.Name)
				assert.Equal(t, authzen.Resource{Type: "registry", ID: "agentregistry"}, pdp.evals[0].Resource)
			}
		})
	}
}

// TestError_HumaResponse checks that huma writes the error as a normal
// problem+json body with the contract status, without leaking the cause.
func TestError_HumaResponse(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		status    int
		challenge bool
	}{
		{"401", unauthenticated(), http.StatusUnauthorized, true},
		{"403", forbidden("not permitted to apply agent team/a"), http.StatusForbidden, false},
		{"404", notFound(`Agent "team"/"a" not found`), http.StatusNotFound, false},
		{"503", unavailable(errPDPDown), http.StatusServiceUnavailable, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, api := humatest.New(t)
			huma.Get(api, "/x", func(context.Context, *struct{}) (*struct{}, error) { return nil, tt.err })
			resp := api.Get("/x")
			require.Equal(t, tt.status, resp.Code)
			assert.Equal(t, "application/problem+json", resp.Header().Get("Content-Type"))
			if tt.challenge {
				assert.Equal(t, "Bearer", resp.Header().Get("WWW-Authenticate"))
			} else {
				assert.Empty(t, resp.Header().Get("WWW-Authenticate"))
			}
			var body map[string]any
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
			assert.Equal(t, float64(tt.status), body["status"])
			assert.Equal(t, http.StatusText(tt.status), body["title"])
			assert.NotEmpty(t, body["detail"])
			assert.NotContains(t, resp.Body.String(), errPDPDown.Error())
		})
	}
}
