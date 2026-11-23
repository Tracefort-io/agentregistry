package openbao

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/secret"
)

// fakeBao is a minimal OpenBao: kubernetes and approle login, token renewal,
// and KV v2 data and metadata on one mount. Tokens are checked like the
// real thing: an unknown or revoked token is a 403.
type fakeBao struct {
	t *testing.T

	mu     sync.Mutex
	kv     map[string]map[string]any // "<namespace>|<path under the mount>" -> data
	tokens map[string]bool
	// loginNamespaces records the namespace of each login.
	loginNamespaces []string
	next            int
	logins          int
	renewals        int
	ttl             int64
	denied          string // a path prefix the policy refuses
	headers         http.Header
}

func newFakeBao(t *testing.T) (*fakeBao, *httptest.Server) {
	f := &fakeBao{t: t, kv: map[string]map[string]any{}, tokens: map[string]bool{}, ttl: 3600}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeBao) issue() map[string]any {
	f.next++
	tok := "s.token-" + string(rune('a'+f.next))
	f.tokens[tok] = true
	return map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": f.ttl, "renewable": true}}
}

func (f *fakeBao) revokeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = map[string]bool{}
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = r.Header.Clone()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	reply := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	var in map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&in)
	}

	switch path {
	case "auth/kubernetes/login":
		if in["role"] != "agentregistry" || in["jwt"] != "sa-jwt" {
			reply(http.StatusBadRequest, map[string]any{"errors": []string{"invalid role or token"}})
			return
		}
		f.logins++
		f.loginNamespaces = append(f.loginNamespaces, r.Header.Get("X-Vault-Namespace"))
		reply(http.StatusOK, f.issue())
		return
	case "auth/approle/login":
		if in["role_id"] != "role-1" || in["secret_id"] != "secret-1" {
			reply(http.StatusBadRequest, map[string]any{"errors": []string{"invalid credentials"}})
			return
		}
		f.logins++
		reply(http.StatusOK, f.issue())
		return
	}

	if !f.tokens[r.Header.Get("X-Vault-Token")] {
		reply(http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	if path == "auth/token/renew-self" {
		f.renewals++
		tok := r.Header.Get("X-Vault-Token")
		reply(http.StatusOK, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": f.ttl, "renewable": true}})
		return
	}
	if f.denied != "" && strings.Contains(path, f.denied) {
		reply(http.StatusForbidden, map[string]any{"errors": []string{"1 error occurred: permission denied"}})
		return
	}
	switch {
	case strings.HasPrefix(path, "agentregistry/data/"):
		key := r.Header.Get("X-Vault-Namespace") + "|" + strings.TrimPrefix(path, "agentregistry/data/")
		switch r.Method {
		case http.MethodPost:
			data, _ := in["data"].(map[string]any)
			f.kv[key] = data
			reply(http.StatusOK, map[string]any{"data": map[string]any{"version": 1}})
		case http.MethodGet:
			data, ok := f.kv[key]
			if !ok {
				reply(http.StatusNotFound, map[string]any{"errors": []string{}})
				return
			}
			reply(http.StatusOK, map[string]any{"data": map[string]any{"data": data}})
		}
	case strings.HasPrefix(path, "agentregistry/metadata/") && r.Method == http.MethodDelete:
		delete(f.kv, r.Header.Get("X-Vault-Namespace")+"|"+strings.TrimPrefix(path, "agentregistry/metadata/"))
		reply(http.StatusNoContent, nil)
	default:
		reply(http.StatusNotFound, map[string]any{"errors": []string{"no handler for route"}})
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cred")
	require.NoError(t, os.WriteFile(p, []byte(content+"\n"), 0o600))
	return p
}

func newStore(t *testing.T, srv *httptest.Server, auth Auth, now func() time.Time) *Store {
	t.Helper()
	c, err := NewClient(ClientConfig{Address: srv.URL, Namespace: "team-a", Auth: auth, Now: now})
	require.NoError(t, err)
	s, err := New(c, "agentregistry", "secrets")
	require.NoError(t, err)
	return s
}

func k8sAuth(t *testing.T) Auth {
	return KubernetesAuth{Role: "agentregistry", TokenFile: writeFile(t, "sa-jwt")}
}

func TestStoreRoundTrip(t *testing.T) {
	f, srv := newFakeBao(t)
	s := newStore(t, srv, k8sAuth(t), nil)
	ctx := context.Background()

	data := map[string][]byte{"api-key": []byte("s3cr3t"), "binary": {0, 255, 10, 13}}
	require.NoError(t, s.Put(ctx, "team", "llm", data))

	got, err := s.Get(ctx, "team", "llm")
	require.NoError(t, err)
	assert.Equal(t, data, got)

	stored := f.kv["team-a|secrets/team/llm"]
	assert.Equal(t, "czNjcjN0", stored["api-key"], "stored base64-encoded")
	assert.Equal(t, "team-a", f.headers.Get("X-Vault-Namespace"))
	assert.Equal(t, 1, f.logins, "one login, reused")

	require.NoError(t, s.Delete(ctx, "team", "llm"))
	_, err = s.Get(ctx, "team", "llm")
	require.ErrorIs(t, err, secret.ErrPayloadNotFound)
	require.NoError(t, s.Delete(ctx, "team", "llm"), "deleting a missing payload is not an error")

	require.NoError(t, s.Put(ctx, "", "defaulted", data))
	assert.Contains(t, f.kv, "team-a|secrets/default/defaulted", "an empty namespace is the default namespace")
}

func TestStoreRejectsEscapingNames(t *testing.T) {
	_, srv := newFakeBao(t)
	s := newStore(t, srv, k8sAuth(t), nil)
	for _, name := range []string{"..", ".", "a/b", `a\b`, ""} {
		require.Error(t, s.Put(context.Background(), "team", name, map[string][]byte{"k": []byte("v")}), "name %q", name)
	}
	require.Error(t, s.Put(context.Background(), "..", "x", nil), "namespace ..")
	_, err := New(s.client, "", "secrets")
	require.Error(t, err, "a mount is required")
	_, err = New(s.client, "agentregistry", "a/../b")
	require.Error(t, err)
}

func TestClientRenewsAndLogsInAgain(t *testing.T) {
	f, srv := newFakeBao(t)
	f.ttl = 60
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := newStore(t, srv, k8sAuth(t), clock)
	ctx := context.Background()
	put := func() { require.NoError(t, s.Put(ctx, "team", "x", map[string][]byte{"k": []byte("v")})) }

	put()
	assert.Equal(t, 1, f.logins)

	now = now.Add(30 * time.Second) // half the TTL left: keep the token
	put()
	assert.Equal(t, 0, f.renewals)

	now = now.Add(15 * time.Second) // under a third left: renew
	put()
	assert.Equal(t, 1, f.renewals)
	assert.Equal(t, 1, f.logins)

	f.revokeAll() // a revoked token is refused with 403: log in again and retry
	put()
	assert.Equal(t, 2, f.logins)

	now = now.Add(2 * time.Hour) // expired: log in again
	put()
	assert.Equal(t, 3, f.logins)
}

func TestStorePolicyDenial(t *testing.T) {
	f, srv := newFakeBao(t)
	f.denied = "secrets/forbidden"
	s := newStore(t, srv, k8sAuth(t), nil)
	err := s.Put(context.Background(), "forbidden", "x", map[string][]byte{"k": []byte("do-not-leak")})
	require.ErrorIs(t, err, ErrForbidden)
	assert.Equal(t, 2, f.logins, "one fresh login before giving up")
	assert.NotContains(t, err.Error(), "do-not-leak")
	assert.NotContains(t, err.Error(), "s.token", "no token in errors")
	assert.Contains(t, err.Error(), "forbidden/x")
}

func TestAuthMethods(t *testing.T) {
	_, srv := newFakeBao(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		auth    Auth
		wantErr string
	}{
		{"kubernetes", k8sAuth(t), ""},
		{"approle", AppRoleAuth{RoleIDFile: writeFile(t, "role-1"), SecretIDFile: writeFile(t, "secret-1")}, ""},
		{"kubernetes with a wrong token", KubernetesAuth{Role: "agentregistry", TokenFile: writeFile(t, "other")}, "invalid role or token"},
		{"kubernetes without a role", KubernetesAuth{TokenFile: writeFile(t, "sa-jwt")}, "needs a role"},
		{"approle with a missing file", AppRoleAuth{RoleIDFile: "/nonexistent", SecretIDFile: writeFile(t, "secret-1")}, "read AppRole role ID"},
		{"empty token file", TokenAuth{TokenFile: writeFile(t, "")}, "is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t, srv, tt.auth, nil)
			err := s.Check(ctx)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestNewClientValidation(t *testing.T) {
	for _, addr := range []string{"", "openbao:8200", "ftp://openbao"} {
		_, err := NewClient(ClientConfig{Address: addr, Auth: TokenAuth{}})
		require.Error(t, err, addr)
	}
	_, err := NewClient(ClientConfig{Address: "https://openbao:8200"})
	require.Error(t, err, "auth is required")
}

func TestStoreOrgNamespaces(t *testing.T) {
	f, srv := newFakeBao(t)
	c, err := NewClient(ClientConfig{Address: srv.URL, Namespace: "team-a", Auth: k8sAuth(t)})
	require.NoError(t, err)
	s, err := New(c, "agentregistry", "secrets", WithOrgNamespaces("org-"))
	require.NoError(t, err)
	ctx := context.Background()

	data := map[string][]byte{"token": []byte("t0k")}
	require.NoError(t, s.Put(ctx, "acme", "crm", data))
	require.NoError(t, s.Put(ctx, "", "crm", map[string][]byte{"token": []byte("other")}))

	assert.Contains(t, f.kv, "team-a/org-acme|secrets/crm", "acme's Secret lives in its own namespace, without a namespace segment")
	assert.Contains(t, f.kv, "team-a/org-default|secrets/crm", "the default namespace is an org too")
	got, err := s.Get(ctx, "acme", "crm")
	require.NoError(t, err)
	assert.Equal(t, data, got, "orgs don't see each other's Secret of the same name")
	assert.Equal(t, []string{"team-a"}, f.loginNamespaces, "the login stays in the client's namespace")

	assert.Equal(t, "org-acme", s.OrgNamespace("acme"))
	assert.Equal(t, "org-default", s.OrgNamespace(""))
	path, err := s.PayloadPath("acme", "crm")
	require.NoError(t, err)
	assert.Equal(t, "agentregistry/data/secrets/crm", path, "what a policy in org-acme names")

	require.NoError(t, s.Delete(ctx, "acme", "crm"))
	_, err = s.Get(ctx, "acme", "crm")
	require.ErrorIs(t, err, secret.ErrPayloadNotFound)
	_, err = s.Get(ctx, "default", "crm")
	require.NoError(t, err, "deleting acme's Secret leaves default's alone")

	require.NoError(t, s.Check(ctx))
}

func TestStoreOrgNamespaceValidation(t *testing.T) {
	_, srv := newFakeBao(t)
	c, err := NewClient(ClientConfig{Address: srv.URL, Auth: k8sAuth(t)})
	require.NoError(t, err)
	for _, prefix := range []string{"", "org/", "../", "a b"} {
		_, err := New(c, "agentregistry", "secrets", WithOrgNamespaces(prefix))
		require.Error(t, err, "prefix %q", prefix)
	}
	s, err := New(c, "agentregistry", "secrets", WithOrgNamespaces("org-"))
	require.NoError(t, err)
	for _, namespace := range []string{"..", "a/b"} {
		require.Error(t, s.Put(context.Background(), namespace, "x", map[string][]byte{"k": nil}), "namespace %q", namespace)
	}
	plain, err := New(c, "agentregistry", "secrets")
	require.NoError(t, err)
	assert.Empty(t, plain.OrgNamespace("acme"), "without org namespaces there is none")
}
