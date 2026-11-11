//go:build authe2e

// Package authe2e checks a running registry with
// AGENT_REGISTRY_AUTH_MODE=required against a real identity provider and
// AuthZEN PDP: each role (admin, writer, reader) and an anonymous caller must
// get exactly the access that docs/auth/authz-matrix.md and the reference
// policy docs/auth/authzen/registry.rego describe.
//
// It runs with `make test-auth-e2e` and is configured through the
// environment (see test/authe2e/README.md):
//
//	AUTH_E2E_URLS        comma-separated base URLs to test, for example the
//	                     gateway and a port-forward straight to the registry
//	AUTH_E2E_NAMESPACE   namespace for the test resources (default "default")
//	AUTH_E2E_KEEP        "true" leaves the test resources in place for
//	                     inspection (deletes are then not exercised)
//	AUTH_E2E_<ROLE>_TOKEN                 a bearer token for ROLE, or
//	AUTH_E2E_TOKEN_URL, AUTH_E2E_CLIENT_ID and
//	AUTH_E2E_<ROLE>_USERNAME / _PASSWORD  to get one with the password grant
//
// ROLE is ADMIN, WRITER or READER. A role without credentials is skipped; the
// admin is required, since it creates and removes the fixtures.
package authe2e

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// role is what a test user may do under the reference policy.
type role struct {
	name     string
	envName  string
	admin    bool
	write    bool // apply and delete registry resources
	secrets  bool // read and list Secrets
	promptOK []string
}

var roles = []role{
	{name: "admin", envName: "ADMIN", admin: true, write: true, secrets: true,
		promptOK: []string{"read", "list", "apply", "delete"}},
	{name: "writer", envName: "WRITER", write: true, secrets: true,
		promptOK: []string{"read", "list", "apply", "delete"}},
	{name: "reader", envName: "READER",
		promptOK: []string{"read", "list"}},
}

// secretValue is written to the fixture Secret and must never be returned.
const secretValue = "authe2e-must-not-leak"

var httpClient = &http.Client{Timeout: 15 * time.Second}

func TestRoles(t *testing.T) {
	urls := splitList(os.Getenv("AUTH_E2E_URLS"))
	if len(urls) == 0 {
		t.Skip("AUTH_E2E_URLS not set; see test/authe2e/README.md")
	}
	ns := os.Getenv("AUTH_E2E_NAMESPACE")
	if ns == "" {
		ns = "default"
	}
	keep := os.Getenv("AUTH_E2E_KEEP") == "true"

	tokens := map[string]string{}
	for _, r := range roles {
		if tok := tokenFor(t, r.envName); tok != "" {
			tokens[r.name] = tok
		}
	}
	require.NotEmpty(t, tokens["admin"], "admin credentials are required (AUTH_E2E_ADMIN_*)")

	for _, base := range urls {
		base = strings.TrimRight(base, "/")
		t.Run(base, func(t *testing.T) {
			c := client{t: t, base: base}
			suffix := randomSuffix(t)
			prompt := promptDoc(ns, "authe2e-"+suffix)
			secret := secretDoc(ns, "authe2e-"+suffix)

			admin := tokens["admin"]
			c.applied(admin, prompt)
			c.applied(admin, secret)
			if keep {
				t.Logf("keeping Prompt and Secret %s/authe2e-%s", ns, suffix)
			} else {
				t.Cleanup(func() {
					c.do(http.MethodDelete, "/v0/apply", admin, secret)
					c.do(http.MethodDelete, "/v0/apply", admin, prompt)
				})
			}

			t.Run("anonymous", func(t *testing.T) {
				c := client{t: t, base: base}
				// The registry serves health without a token; a gateway in
				// front may still require one.
				assert.Contains(t, []int{http.StatusOK, http.StatusUnauthorized}, c.status(http.MethodGet, "/v0/health", "", ""), "health")
				assert.Equal(t, http.StatusUnauthorized, c.status(http.MethodGet, "/v0/prompts", "", ""))
				assert.Equal(t, http.StatusUnauthorized, c.status(http.MethodGet, "/v0/me", "", ""))
				assert.Equal(t, http.StatusUnauthorized, c.status(http.MethodPost, "/v0/apply", "", prompt))
				assert.Equal(t, http.StatusUnauthorized, c.status(http.MethodGet, "/v0/prompts", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", ""), "alg=none token")
				assert.Equal(t, http.StatusUnauthorized, c.status(http.MethodGet, "/v0/prompts", forgedHS256(), ""), "HMAC token")
			})

			for _, r := range roles {
				tok := tokens[r.name]
				t.Run(r.name, func(t *testing.T) {
					if tok == "" {
						t.Skipf("no credentials for %s (AUTH_E2E_%s_*)", r.name, r.envName)
					}
					c := client{t: t, base: base}
					checkMe(t, c, tok, ns, r)

					assert.Equal(t, http.StatusOK, c.status(http.MethodGet, "/v0/prompts?namespace="+ns, tok, ""), "list prompts")
					assert.Equal(t, http.StatusOK, c.status(http.MethodGet, "/v0/prompts/authe2e-"+suffix+"?namespace="+ns, tok, ""), "read the fixture prompt")

					secretPath := "/v0/secrets/authe2e-" + suffix + "?namespace=" + ns
					if r.secrets {
						assert.Equal(t, http.StatusOK, c.status(http.MethodGet, "/v0/secrets?namespace="+ns, tok, ""), "list secrets")
						code, body := c.do(http.MethodGet, secretPath, tok, "")
						assert.Equal(t, http.StatusOK, code, "read the fixture secret")
						assert.NotContains(t, body, secretValue, "secret values are never returned")
					} else {
						assert.Equal(t, http.StatusForbidden, c.status(http.MethodGet, "/v0/secrets?namespace="+ns, tok, ""), "list secrets")
						assert.Equal(t, http.StatusNotFound, c.status(http.MethodGet, secretPath, tok, ""), "a secret it may not read does not exist for it")
					}

					own := promptDoc(ns, "authe2e-"+r.name+"-"+suffix)
					if r.write {
						c.applied(tok, own)
						assert.Equal(t, http.StatusOK, c.status(http.MethodGet, "/v0/prompts/authe2e-"+r.name+"-"+suffix+"?namespace="+ns, tok, ""), "read its own prompt")
						if keep {
							t.Logf("keeping Prompt %s/authe2e-%s-%s; delete was not exercised", ns, r.name, suffix)
						} else {
							c.deleted(tok, own)
						}
					} else {
						c.denied(http.MethodPost, tok, own, "apply")
						c.denied(http.MethodDelete, tok, prompt, "delete the fixture")
						assert.Equal(t, http.StatusOK, c.status(http.MethodGet, "/v0/prompts/authe2e-"+suffix+"?namespace="+ns, admin, ""), "the fixture survives")
					}
				})
			}
		})
	}
}

// checkMe compares GET /v0/me with what the role may do.
func checkMe(t *testing.T, c client, tok, ns string, r role) {
	t.Helper()
	code, body := c.do(http.MethodGet, "/v0/me?namespace="+ns, tok, "")
	require.Equal(t, http.StatusOK, code, body)
	var me struct {
		Authenticated bool                `json:"authenticated"`
		Enforced      bool                `json:"enforced"`
		Admin         bool                `json:"admin"`
		Permissions   map[string][]string `json:"permissions"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &me), body)
	assert.True(t, me.Authenticated, "authenticated")
	assert.True(t, me.Enforced, "permissions come from the PDP")
	assert.Equal(t, r.admin, me.Admin, "admin")
	assert.Subset(t, me.Permissions["Prompt"], r.promptOK, "Prompt permissions")
	if !r.write {
		assert.NotContains(t, me.Permissions["Prompt"], "apply")
		assert.NotContains(t, me.Permissions["Prompt"], "delete")
	}
	if r.secrets {
		assert.Contains(t, me.Permissions["Secret"], "read")
	} else {
		assert.Empty(t, me.Permissions["Secret"], "Secret permissions")
	}
}

type client struct {
	t    *testing.T
	base string
}

func (c client) do(method, path, token, yamlBody string) (int, string) {
	c.t.Helper()
	var body io.Reader
	if yamlBody != "" {
		body = strings.NewReader(yamlBody)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	require.NoError(c.t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if yamlBody != "" {
		req.Header.Set("Content-Type", "application/yaml")
	}
	resp, err := httpClient.Do(req)
	require.NoError(c.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(c.t, err)
	return resp.StatusCode, string(raw)
}

func (c client) status(method, path, token, yamlBody string) int {
	c.t.Helper()
	code, _ := c.do(method, path, token, yamlBody)
	return code
}

// batchResult is one document's outcome from POST or DELETE /v0/apply.
type batchResult struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

func (c client) batch(method, token, doc string) (int, []batchResult, string) {
	c.t.Helper()
	code, body := c.do(method, "/v0/apply", token, doc)
	var out struct {
		Results []batchResult `json:"results"`
	}
	if code == http.StatusOK {
		require.NoError(c.t, json.Unmarshal([]byte(body), &out), body)
	}
	return code, out.Results, body
}

func (c client) applied(token, doc string) {
	c.t.Helper()
	code, results, body := c.batch(http.MethodPost, token, doc)
	require.Equal(c.t, http.StatusOK, code, body)
	require.Len(c.t, results, 1, body)
	require.Contains(c.t, []string{"created", "configured", "unchanged"}, results[0].Status, body)
}

func (c client) deleted(token, doc string) {
	c.t.Helper()
	code, results, body := c.batch(http.MethodDelete, token, doc)
	require.Equal(c.t, http.StatusOK, code, body)
	require.Len(c.t, results, 1, body)
	assert.Equal(c.t, "deleted", results[0].Status, body)
}

// denied accepts either layer's refusal: a gateway answers 403, the
// registry's batch endpoint reports a forbidden document with HTTP 200.
func (c client) denied(method, token, doc, what string) {
	c.t.Helper()
	code, results, body := c.batch(method, token, doc)
	if code == http.StatusForbidden {
		return
	}
	require.Equal(c.t, http.StatusOK, code, "%s: %s", what, body)
	require.Len(c.t, results, 1, body)
	assert.Equal(c.t, "failed", results[0].Status, "%s: %s", what, body)
	assert.Contains(c.t, results[0].Error, "forbidden", "%s: %s", what, body)
}

func promptDoc(ns, name string) string {
	return fmt.Sprintf(`apiVersion: ar.dev/v1alpha1
kind: Prompt
metadata:
  namespace: %s
  name: %s
spec:
  description: Created by the authe2e test; deleted again.
  content: hello
`, ns, name)
}

func secretDoc(ns, name string) string {
	return fmt.Sprintf(`apiVersion: ar.dev/v1alpha1
kind: Secret
metadata:
  namespace: %s
  name: %s
spec:
  stringData:
    api-key: %s
`, ns, name, secretValue)
}

// tokenFor returns AUTH_E2E_<ROLE>_TOKEN, or a password-grant token, or "".
func tokenFor(t *testing.T, envName string) string {
	t.Helper()
	if tok := os.Getenv("AUTH_E2E_" + envName + "_TOKEN"); tok != "" {
		return tok
	}
	user := os.Getenv("AUTH_E2E_" + envName + "_USERNAME")
	tokenURL := os.Getenv("AUTH_E2E_TOKEN_URL")
	if user == "" || tokenURL == "" {
		return ""
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {os.Getenv("AUTH_E2E_CLIENT_ID")},
		"username":   {user},
		"password":   {os.Getenv("AUTH_E2E_" + envName + "_PASSWORD")},
		"scope":      {"openid"},
	}
	resp, err := httpClient.PostForm(tokenURL, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.AccessToken, "token for %s: %s", user, out.Error)
	return out.AccessToken
}

// forgedHS256 is a token signed with a made-up HMAC key; HMAC is never
// accepted, whatever the key.
func forgedHS256() string {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiJhdHRhY2tlciIsInJvbGVzIjpbInJlZ2lzdHJ5LWFkbWluIl19." +
		"c2lnbmF0dXJlLWRvZXMtbm90LW1hdHRlcg"
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
