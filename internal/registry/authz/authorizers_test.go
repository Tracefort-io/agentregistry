package authz

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

func newPEP(t *testing.T, pdp *mockPDP, mutate func(*Config)) *PEP {
	t.Helper()
	cfg := Config{Client: pdp}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	require.NoError(t, err)
	return p
}

func TestNew_RequiresClient(t *testing.T) {
	_, err := New(Config{})
	assert.Error(t, err)
}

func TestAuthorizers_CoverKinds(t *testing.T) {
	p := newPEP(t, newMockPDP(nil), func(c *Config) { c.ExtraKinds = []string{"Widget"} })
	hooks := p.Authorizers()
	filters := p.ListFilters()
	for _, kind := range append(append([]string{}, BuiltinKinds...), "Widget") {
		assert.NotNil(t, hooks[kind], kind)
		assert.NotNil(t, filters[kind], kind)
	}
	assert.Len(t, hooks, len(BuiltinKinds)+1)
}

func TestAuthorize_KindVerbMapping(t *testing.T) {
	type tc struct {
		verb, tag          string
		wantAction, wantID string
		wantTag            bool
		namespace          string
	}
	for _, kind := range append(append([]string{}, BuiltinKinds...), "Widget") {
		tagged := v1alpha1.IsTaggedArtifactKind(kind)
		cases := []tc{
			{verb: "get", tag: "v1", wantAction: "read", wantID: "team/thing", namespace: "team", wantTag: tagged},
			{verb: "get", wantAction: "read", wantID: "team/thing", namespace: "team"},
			{verb: "list", wantAction: "list", wantID: "team/*", namespace: "team"},
			{verb: "list", wantAction: "list", wantID: "*", namespace: ""},
			{verb: "delete", tag: "v2", wantAction: "delete", wantID: "team/thing", namespace: "team", wantTag: tagged},
		}
		if kind != v1alpha1.KindDeployment {
			cases = append(cases, tc{verb: "apply", tag: "v3", wantAction: "apply", wantID: "team/thing", namespace: "team", wantTag: tagged})
		}
		for _, c := range cases {
			t.Run(kind+"/"+c.verb+"/"+c.wantID+"/"+c.tag, func(t *testing.T) {
				pdp := newMockPDP(nil)
				p := newPEP(t, pdp, func(cfg *Config) { cfg.ExtraKinds = []string{"Widget"} })
				in := types.AuthorizeInput{Verb: c.verb, Kind: kind, Namespace: c.namespace, Tag: c.tag}
				if c.verb != "list" {
					in.Name = "thing"
				}
				require.NoError(t, p.Authorizers()[kind](userCtx(alice()), in))
				require.Len(t, pdp.evals, 1)
				req := pdp.evals[0]
				assert.Equal(t, c.wantAction, req.Action.Name)
				assert.Equal(t, strings.ToLower(kind), req.Resource.Type)
				assert.Equal(t, c.wantID, req.Resource.ID)
				assert.Equal(t, kind, req.Resource.Properties["kind"])
				_, hasTag := req.Resource.Properties["tag"]
				assert.Equal(t, c.wantTag, hasTag)
				assert.Equal(t, authzen.Context{"pep": "agentregistry", "request_id": "req-1"}, req.Context)
				assert.Equal(t, "alice-sub", req.Subject.ID)
			})
		}
	}
}

func TestAuthorize_StatusMapping(t *testing.T) {
	deny := func(authzen.EvaluationRequest) bool { return false }
	tests := []struct {
		name       string
		ctx        context.Context
		verb       string
		decide     func(authzen.EvaluationRequest) bool
		pdpErr     error
		wantStatus int
		wantIs     error
		wantCalls  int
	}{
		{name: "permit get", ctx: userCtx(alice()), verb: "get", wantCalls: 1},
		{name: "deny get is 404", ctx: userCtx(alice()), verb: "get", decide: deny, wantStatus: 404, wantIs: auth.ErrForbidden, wantCalls: 1},
		{name: "deny list is 403", ctx: userCtx(alice()), verb: "list", decide: deny, wantStatus: 403, wantIs: auth.ErrForbidden, wantCalls: 1},
		{name: "deny apply is 403", ctx: userCtx(alice()), verb: "apply", decide: deny, wantStatus: 403, wantIs: auth.ErrForbidden, wantCalls: 1},
		{name: "deny delete is 403", ctx: userCtx(alice()), verb: "delete", decide: deny, wantStatus: 403, wantIs: auth.ErrForbidden, wantCalls: 1},
		{name: "pdp failure on get is 503", ctx: userCtx(alice()), verb: "get", pdpErr: errPDPDown, wantStatus: 503, wantIs: auth.ErrForbidden, wantCalls: 1},
		{name: "pdp failure on apply is 503", ctx: userCtx(alice()), verb: "apply", pdpErr: errPDPDown, wantStatus: 503, wantIs: errPDPDown, wantCalls: 1},
		{name: "unknown verb is 403", ctx: userCtx(alice()), verb: "patch", wantStatus: 403, wantIs: auth.ErrForbidden},
		{name: "no session is 401", ctx: context.Background(), verb: "get", wantStatus: 401, wantIs: auth.ErrUnauthenticated},
		{name: "unauthenticated principal is 401", ctx: userCtx(auth.Principal{Subject: "x"}), verb: "get", wantStatus: 401, wantIs: auth.ErrUnauthenticated},
		{name: "system session skips pdp", ctx: auth.WithSystemContext(context.Background()), verb: "delete", decide: deny},
		{name: "public session asks as anonymous", ctx: auth.WithPublicContext(context.Background()), verb: "get", wantCalls: 1},
		{name: "public session denied get is 404", ctx: auth.WithPublicContext(context.Background()), verb: "get", decide: deny, wantStatus: 404, wantIs: auth.ErrForbidden, wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(tt.decide)
			pdp.err = tt.pdpErr
			p := newPEP(t, pdp, nil)
			err := p.Authorize(tt.ctx, types.AuthorizeInput{Verb: tt.verb, Kind: v1alpha1.KindAgent, Namespace: "default", Name: "a"})
			assert.Equal(t, tt.wantCalls, pdp.calls())
			if tt.wantStatus == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.wantStatus, StatusOf(err))
			assert.ErrorIs(t, err, tt.wantIs)
			if tt.wantStatus == http.StatusUnauthorized {
				assert.False(t, errors.Is(err, auth.ErrForbidden))
			} else {
				assert.False(t, errors.Is(err, auth.ErrUnauthenticated))
			}
		})
	}
}

func TestAuthorize_PublicSubject(t *testing.T) {
	pdp := newMockPDP(nil)
	p := newPEP(t, pdp, nil)
	require.NoError(t, p.Authorize(auth.WithPublicContext(context.Background()),
		types.AuthorizeInput{Verb: "list", Kind: v1alpha1.KindMCPServer}))
	require.Len(t, pdp.evals, 1)
	assert.Equal(t, authzen.Subject{Type: "anonymous", ID: "anonymous"}, pdp.evals[0].Subject)
	assert.Equal(t, authzen.Context{"pep": "agentregistry"}, pdp.evals[0].Context, "no request_id when none is set")
}

func TestSubjectFor(t *testing.T) {
	tests := []struct {
		name     string
		p        auth.Principal
		wantType string
		check    func(t *testing.T, s authzen.Subject)
	}{
		{
			name: "user", p: alice(), wantType: "user",
			check: func(t *testing.T, s authzen.Subject) {
				assert.Equal(t, "alice-sub", s.ID)
				assert.Equal(t, "https://idp.example", s.Properties["iss"])
				assert.Equal(t, "alice", s.Properties["username"])
				assert.Equal(t, "registry-ui", s.Properties["client_id"])
				assert.Equal(t, []string{"registry-reader"}, s.Properties["roles"])
				assert.Equal(t, []string{"eng"}, s.Properties["groups"])
				assert.NotContains(t, s.Properties, "act")
			},
		},
		{
			name: "client credentials: sub equals client id", wantType: "client",
			p: auth.Principal{Subject: "svc", Issuer: "https://idp", ClientID: "svc"},
			check: func(t *testing.T, s authzen.Subject) {
				assert.Equal(t, []string{}, s.Properties["roles"], "roles always present")
				assert.Equal(t, []string{}, s.Properties["groups"])
				assert.NotContains(t, s.Properties, "username")
			},
		},
		{
			name: "client credentials: client_id claim without username", wantType: "client",
			p: auth.Principal{Subject: "uuid-1", Issuer: "https://idp", ClientID: "svc", Claims: map[string]any{"client_id": "svc"}},
		},
		{
			name: "user with client_id claim and username", wantType: "user",
			p: auth.Principal{Subject: "uuid-2", Issuer: "https://idp", Claims: map[string]any{"client_id": "ui", "preferred_username": "bob"}},
		},
		{
			name: "delegated", wantType: "user",
			p: auth.Principal{Subject: "bob", Issuer: "https://idp", Actor: []auth.Actor{{Subject: "agent", Issuer: "https://idp"}}},
			check: func(t *testing.T, s authzen.Subject) {
				assert.Equal(t, []map[string]any{{"sub": "agent", "iss": "https://idp"}}, s.Properties["act"])
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(nil)
			p := newPEP(t, pdp, nil)
			require.NoError(t, p.Authorize(userCtx(tt.p), types.AuthorizeInput{Verb: "get", Kind: v1alpha1.KindAgent, Namespace: "d", Name: "a"}))
			s := pdp.evals[0].Subject
			assert.Equal(t, tt.wantType, s.Type)
			if tt.check != nil {
				tt.check(t, s)
			}
		})
	}
}

func TestConfig_IsClientOverride(t *testing.T) {
	pdp := newMockPDP(nil)
	p := newPEP(t, pdp, func(c *Config) { c.IsClient = func(auth.Principal) bool { return true } })
	require.NoError(t, p.Authorize(userCtx(alice()), types.AuthorizeInput{Verb: "get", Kind: v1alpha1.KindAgent, Namespace: "d", Name: "a"}))
	assert.Equal(t, "client", pdp.evals[0].Subject.Type)
}

func deployment(target, runtime v1alpha1.ResourceRef) *v1alpha1.Deployment {
	return &v1alpha1.Deployment{
		Metadata: v1alpha1.ObjectMeta{Namespace: "team", Name: "dep"},
		Spec:     v1alpha1.DeploymentSpec{TargetRef: target, RuntimeRef: runtime},
	}
}

func TestAuthorize_DeploymentApply(t *testing.T) {
	agentRef := v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "bot", Tag: "v1"}
	runtimeRef := v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Namespace: "shared", Name: "k8s"}
	denyID := func(id string) func(authzen.EvaluationRequest) bool {
		return func(r authzen.EvaluationRequest) bool { return r.Resource.ID != id }
	}
	tests := []struct {
		name       string
		obj        v1alpha1.Object
		decide     func(authzen.EvaluationRequest) bool
		pdpErr     error
		shortBy    int
		wantStatus int
		wantBatch  bool
	}{
		{name: "all permit", obj: deployment(agentRef, runtimeRef), wantBatch: true},
		{name: "target denied", obj: deployment(agentRef, runtimeRef), decide: denyID("team/bot"), wantStatus: 403, wantBatch: true},
		{name: "runtime denied", obj: deployment(agentRef, runtimeRef), decide: denyID("shared/k8s"), wantStatus: 403, wantBatch: true},
		{name: "deployment denied", obj: deployment(agentRef, runtimeRef), decide: denyID("team/dep"), wantStatus: 403, wantBatch: true},
		{name: "pdp failure", obj: deployment(agentRef, runtimeRef), pdpErr: errPDPDown, wantStatus: 503, wantBatch: true},
		{name: "short batch without deny", obj: deployment(agentRef, runtimeRef), shortBy: 1, wantStatus: 503, wantBatch: true},
		{name: "nil object", obj: nil, wantStatus: 403},
		{name: "target kind invalid", obj: deployment(v1alpha1.ResourceRef{Kind: "Skill", Name: "s"}, runtimeRef), wantStatus: 403},
		{name: "runtime missing", obj: deployment(agentRef, v1alpha1.ResourceRef{}), wantStatus: 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(tt.decide)
			pdp.err = tt.pdpErr
			pdp.shortBy = tt.shortBy
			p := newPEP(t, pdp, nil)
			err := p.Authorize(userCtx(alice()), types.AuthorizeInput{
				Verb: "apply", Kind: v1alpha1.KindDeployment, Namespace: "team", Name: "dep", Object: tt.obj,
			})
			assert.Empty(t, pdp.evals, "deployment apply uses one batch")
			if !tt.wantBatch {
				assert.Empty(t, pdp.batches)
			} else {
				require.Len(t, pdp.batches, 1)
				b := pdp.batches[0]
				assert.Equal(t, authzen.DenyOnFirstDeny, b.Semantic())
				require.Len(t, b.Evaluations, 3)
				assert.Equal(t, "deploy", b.Evaluations[0].Action.Name)
				assert.Equal(t, authzen.Resource{Type: "agent", ID: "team/bot", Properties: map[string]any{
					"kind": "Agent", "namespace": "team", "name": "bot", "tag": "v1",
				}}, *b.Evaluations[0].Resource, "target namespace defaults to the deployment's")
				assert.Equal(t, "read", b.Evaluations[1].Action.Name)
				assert.Equal(t, "runtime", b.Evaluations[1].Resource.Type)
				assert.Equal(t, "shared/k8s", b.Evaluations[1].Resource.ID)
				assert.Equal(t, "apply", b.Evaluations[2].Action.Name)
				assert.Equal(t, "deployment", b.Evaluations[2].Resource.Type)
				assert.Equal(t, "team/dep", b.Evaluations[2].Resource.ID)
				assert.Equal(t, "alice-sub", b.Subject.ID)
			}
			if tt.wantStatus == 0 {
				require.NoError(t, err)
				return
			}
			assert.Equal(t, tt.wantStatus, StatusOf(err))
			assert.ErrorIs(t, err, auth.ErrForbidden)
		})
	}
}

func TestAuthorize_DeploymentOtherVerbsAreOwnResource(t *testing.T) {
	for _, verb := range []string{"get", "list", "delete"} {
		pdp := newMockPDP(nil)
		p := newPEP(t, pdp, nil)
		require.NoError(t, p.Authorize(userCtx(alice()), types.AuthorizeInput{
			Verb: verb, Kind: v1alpha1.KindDeployment, Namespace: "team", Name: "dep",
			Object: deployment(v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "bot"}, v1alpha1.ResourceRef{Name: "rt"}),
		}))
		require.Len(t, pdp.evals, 1, verb)
		assert.Equal(t, "deployment", pdp.evals[0].Resource.Type)
		assert.Empty(t, pdp.batches)
	}
}
