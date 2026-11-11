package me

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

type session struct{ p auth.Principal }

func (s session) Principal() auth.Principal { return s.p }

func newAPI(t *testing.T, cfg Config, s auth.Session) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t)
	if s != nil {
		api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
			next(huma.WithContext(ctx, auth.AuthSessionTo(ctx.Context(), s)))
		})
	}
	Register(api, "/v0", cfg)
	return api
}

func decode(t *testing.T, raw []byte) Body {
	t.Helper()
	var b Body
	require.NoError(t, json.Unmarshal(raw, &b))
	return b
}

var kinds = []string{v1alpha1.KindAgent, v1alpha1.KindPrompt}

func TestMeWithoutAuthorization(t *testing.T) {
	resp := newAPI(t, Config{Kinds: kinds}, nil).Get("/v0/me")
	require.Equal(t, http.StatusOK, resp.Code)

	b := decode(t, resp.Body.Bytes())
	assert.False(t, b.Authenticated)
	assert.False(t, b.Enforced)
	assert.True(t, b.Admin)
	assert.Equal(t, "default", b.Namespace)
	assert.Equal(t, types.KindActions(v1alpha1.KindAgent), b.Permissions[v1alpha1.KindAgent])
}

func TestMeWithAuthorization(t *testing.T) {
	var gotNamespace string
	perms := func(_ context.Context, namespace string) (types.Permissions, error) {
		gotNamespace = namespace
		return types.Permissions{Kinds: map[string][]string{v1alpha1.KindAgent: {"read", "list"}}}, nil
	}
	principal := auth.Principal{
		Subject: "bob-sub", Issuer: "https://idp", Username: "bob",
		Roles: []string{"registry-reader"}, Groups: []string{"eng"},
	}
	api := newAPI(t, Config{Kinds: kinds, Permissions: perms}, session{principal})

	tests := []struct {
		query, wantNamespace, wantScope string
	}{
		{"", "default", "default"},
		{"?namespace=team", "team", "team"},
		{"?namespace=all", "all", ""},
	}
	for _, tt := range tests {
		t.Run(tt.wantNamespace, func(t *testing.T) {
			resp := api.Get("/v0/me" + tt.query)
			require.Equal(t, http.StatusOK, resp.Code)
			b := decode(t, resp.Body.Bytes())

			assert.Equal(t, tt.wantScope, gotNamespace)
			assert.Equal(t, tt.wantNamespace, b.Namespace)
			assert.True(t, b.Authenticated)
			assert.True(t, b.Enforced)
			assert.False(t, b.Admin)
			assert.Equal(t, "bob-sub", b.Subject)
			assert.Equal(t, "bob", b.Username)
			assert.Equal(t, []string{"registry-reader"}, b.Roles)
			assert.Equal(t, map[string][]string{v1alpha1.KindAgent: {"read", "list"}}, b.Permissions)
		})
	}
}

// statusErr is an error carrying an HTTP status, as the PEP's errors do.
type statusErr struct{ status int }

func (e statusErr) Error() string  { return "denied" }
func (e statusErr) GetStatus() int { return e.status }

func TestMePermissionsErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want int
	}{
		{"authorization service unavailable", statusErr{http.StatusServiceUnavailable}, http.StatusServiceUnavailable},
		{"unexpected error", errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			perms := func(context.Context, string) (types.Permissions, error) { return types.Permissions{}, tt.err }
			resp := newAPI(t, Config{Kinds: kinds, Permissions: perms}, nil).Get("/v0/me")
			assert.Equal(t, tt.want, resp.Code)
		})
	}
}

func TestMeRejectsEmptyNamespace(t *testing.T) {
	resp := newAPI(t, Config{Kinds: kinds}, nil).Get("/v0/me?namespace=%20")
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}
