package openbao

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedCall struct {
	method, path, namespace string
	body                    map[string]any
}

func grantsServer(t *testing.T) (*Grants, *[]recordedCall) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls []recordedCall
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path := r.URL.Path[len("/v1/"):]
		if path == "auth/kubernetes/login" {
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok", "lease_duration": 3600}})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		calls = append(calls, recordedCall{r.Method, path, r.Header.Get("X-Vault-Namespace"), body})
		switch {
		case r.Method == "LIST" && path == "sys/namespaces":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": []string{"org-default/", "org-acme/", "platform/"}}})
		case r.Method == "LIST" && path == "auth/jwt-spiffe/role":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": []string{"mcp-crm-1", "admin"}}})
		case r.Method == "LIST":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{Address: srv.URL, Namespace: "tenants", Auth: KubernetesAuth{Role: "r", TokenFile: writeFile(t, "jwt")}})
	require.NoError(t, err)
	g, err := NewGrants(c, "jwt-spiffe")
	require.NoError(t, err)
	return g, &calls
}

func TestGrantsWritesInTheOrgNamespace(t *testing.T) {
	g, calls := grantsServer(t)
	ctx := context.Background()

	require.NoError(t, g.PutPolicy(ctx, "org-acme", "mcp-crm-1", `path "x" {}`))
	require.NoError(t, g.PutRole(ctx, "org-acme", "mcp-crm-1", GrantRole{
		Audience: "openbao", SubjectGlobs: []string{"spiffe://td/org/acme/agent/a/deployment/u/*"}, Policy: "mcp-crm-1", TTLSeconds: 60, NumUses: 1,
	}))
	require.NoError(t, g.DeleteRole(ctx, "org-acme", "mcp-crm-1"))
	require.NoError(t, g.DeletePolicy(ctx, "org-acme", "mcp-crm-1"))

	require.Len(t, *calls, 4)
	policy, role := (*calls)[0], (*calls)[1]
	assert.Equal(t, recordedCall{http.MethodPut, "sys/policies/acl/mcp-crm-1", "tenants/org-acme", map[string]any{"policy": `path "x" {}`}}, policy)
	assert.Equal(t, "auth/jwt-spiffe/role/mcp-crm-1", role.path)
	assert.Equal(t, "tenants/org-acme", role.namespace, "a child of the client's namespace")
	assert.Equal(t, "jwt", role.body["role_type"])
	assert.Equal(t, "sub", role.body["user_claim"])
	assert.Equal(t, "glob", role.body["bound_claims_type"])
	assert.Equal(t, map[string]any{"sub": []any{"spiffe://td/org/acme/agent/a/deployment/u/*"}}, role.body["bound_claims"])
	assert.Equal(t, []any{"openbao"}, role.body["bound_audiences"])
	assert.Equal(t, []any{"mcp-crm-1"}, role.body["token_policies"])
	assert.Equal(t, true, role.body["token_no_default_policy"], "the token gets the grant's policy only")
	assert.InDelta(t, 1, role.body["token_num_uses"], 0)
	assert.Equal(t, http.MethodDelete, (*calls)[2].method)
	assert.Equal(t, "sys/policies/acl/mcp-crm-1", (*calls)[3].path)
}

func TestGrantsListsOnlyWhatItManages(t *testing.T) {
	g, _ := grantsServer(t)
	ctx := context.Background()
	orgs, err := g.ListOrgs(ctx, "org-")
	require.NoError(t, err)
	assert.Equal(t, []string{"org-default", "org-acme"}, orgs)

	roles, err := g.ListRoles(ctx, "org-acme")
	require.NoError(t, err)
	assert.Equal(t, []string{"mcp-crm-1"}, roles, "a role it didn't make is left out")

	policies, err := g.ListPolicies(ctx, "org-acme")
	require.NoError(t, err)
	assert.Empty(t, policies, "a 404 is an empty list")
}

func TestGrantsRefusesNamesItDoesNotManage(t *testing.T) {
	g, calls := grantsServer(t)
	ctx := context.Background()
	role := GrantRole{Audience: "openbao", SubjectGlobs: []string{"x*"}, Policy: "mcp-a", TTLSeconds: 60, NumUses: 1}
	require.Error(t, g.PutPolicy(ctx, "org-acme", "root", "path \"*\" {}"))
	require.Error(t, g.PutPolicy(ctx, "org-acme", "mcp-a/../root", ""))
	require.Error(t, g.PutRole(ctx, "org-acme", "admin", role))
	require.Error(t, g.DeleteRole(ctx, "org-acme", "admin"))
	require.Error(t, g.PutRole(ctx, "org-acme", "mcp-a", GrantRole{Audience: "openbao", Policy: "mcp-a", TTLSeconds: 60, NumUses: 1}),
		"a role must name its subjects")
	require.Error(t, g.PutPolicy(ctx, "../root", "mcp-a", ""), "an org is one namespace segment")
	assert.Empty(t, *calls, "nothing was sent")
}
