//go:build integration

package openbao

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/secret"
)

// policy grants the registry its prefix and nothing else, as the setup guide
// (docs/secrets-openbao.md) does.
const policy = `
path "agentregistry/data/secrets/*"     { capabilities = ["create", "update", "read"] }
path "agentregistry/metadata/secrets/*" { capabilities = ["delete"] }
`

// TestOpenBao runs the store against a real OpenBao, such as a dev server:
//
//	docker run -d -p 127.0.0.1:18200:8200 -e BAO_DEV_ROOT_TOKEN_ID=root \
//	  quay.io/openbao/openbao:2.4.1 server -dev -dev-listen-address=0.0.0.0:8200
//	OPENBAO_TEST_ADDR=http://127.0.0.1:18200 OPENBAO_TEST_ROOT_TOKEN=root \
//	  go test -tags=integration ./pkg/secret/openbao/
func TestOpenBao(t *testing.T) {
	addr, rootToken := os.Getenv("OPENBAO_TEST_ADDR"), os.Getenv("OPENBAO_TEST_ROOT_TOKEN")
	if addr == "" || rootToken == "" {
		t.Skip("OPENBAO_TEST_ADDR and OPENBAO_TEST_ROOT_TOKEN not set")
	}
	ctx := context.Background()
	root, err := NewClient(ClientConfig{Address: addr, Auth: TokenAuth{TokenFile: writeFile(t, rootToken)}})
	require.NoError(t, err)

	// Setup, as an operator would: a KV v2 mount, a policy for the
	// registry's prefix, and an AppRole bound to it.
	ignoreExists := func(err error) {
		if err != nil {
			t.Logf("setup: %v", err)
		}
	}
	ignoreExists(root.Do(ctx, http.MethodPost, "sys/mounts/agentregistry", map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}, nil))
	ignoreExists(root.Do(ctx, http.MethodPost, "sys/auth/approle", map[string]any{"type": "approle"}, nil))
	require.NoError(t, root.Do(ctx, http.MethodPut, "sys/policies/acl/agentregistry", map[string]any{"policy": policy}, nil))
	require.NoError(t, root.Do(ctx, http.MethodPost, "auth/approle/role/agentregistry", map[string]any{"token_policies": []string{"agentregistry"}, "token_ttl": "1h"}, nil))
	var roleID struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	require.NoError(t, root.Do(ctx, http.MethodGet, "auth/approle/role/agentregistry/role-id", nil, &roleID))
	var secretID struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	require.NoError(t, root.Do(ctx, http.MethodPost, "auth/approle/role/agentregistry/secret-id", map[string]any{}, &secretID))

	client, err := NewClient(ClientConfig{Address: addr, Auth: AppRoleAuth{
		RoleIDFile: writeFile(t, roleID.Data.RoleID), SecretIDFile: writeFile(t, secretID.Data.SecretID),
	}})
	require.NoError(t, err)
	store, err := New(client, "agentregistry", "secrets")
	require.NoError(t, err)
	require.NoError(t, store.Check(ctx), "the policy allows the health check")

	data := map[string][]byte{"api-key": []byte("s3cr3t"), "binary": {0, 1, 254, 255}}
	require.NoError(t, store.Put(ctx, "team", "llm", data))
	got, err := store.Get(ctx, "team", "llm")
	require.NoError(t, err)
	assert.Equal(t, data, got)

	// The value is in OpenBao, base64-encoded, where an operator finds it.
	var raw struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	require.NoError(t, root.Do(ctx, http.MethodGet, "agentregistry/data/secrets/team/llm", nil, &raw))
	assert.Equal(t, "czNjcjN0", raw.Data.Data["api-key"])

	// Updating writes a new version; Get returns the latest.
	require.NoError(t, store.Put(ctx, "team", "llm", map[string][]byte{"api-key": []byte("rotated")}))
	got, err = store.Get(ctx, "team", "llm")
	require.NoError(t, err)
	assert.Equal(t, map[string][]byte{"api-key": []byte("rotated")}, got)

	// Delete destroys every version.
	require.NoError(t, store.Delete(ctx, "team", "llm"))
	_, err = store.Get(ctx, "team", "llm")
	require.ErrorIs(t, err, secret.ErrPayloadNotFound)
	err = root.Do(ctx, http.MethodGet, "agentregistry/metadata/secrets/team/llm", nil, nil)
	require.ErrorIs(t, err, ErrNotFound, "no versions left")

	// The policy confines the registry to its prefix.
	outside, err := New(client, "agentregistry", "other")
	require.NoError(t, err)
	require.ErrorIs(t, outside.Put(ctx, "team", "x", data), ErrForbidden)
}
