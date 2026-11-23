package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPServerCredentialValidation(t *testing.T) {
	server := func(namespace string, credential *MCPCredential) *MCPServer {
		return &MCPServer{
			Metadata: ObjectMeta{Namespace: namespace, Name: "crm"},
			Spec: MCPServerSpec{
				Remote:     &MCPRemote{Type: "streamable-http", URL: "https://crm.example.com/mcp"},
				Credential: credential,
			},
		}
	}
	ref := SecretKeyRef{Name: "crm-api", Key: "token"}

	tests := []struct {
		name       string
		namespace  string
		credential *MCPCredential
		wantErr    string
	}{
		{"no credential", "default", nil, ""},
		{"secret key", "default", &MCPCredential{SecretRef: ref}, ""},
		{"header and scheme", "acme", &MCPCredential{SecretRef: ref, Header: "X-Api-Key", Scheme: "Bearer"}, ""},
		{"same namespace named", "acme", &MCPCredential{SecretRef: SecretKeyRef{Namespace: "acme", Name: "crm-api", Key: "token"}}, ""},
		{"default namespace named", "default", &MCPCredential{SecretRef: SecretKeyRef{Namespace: "default", Name: "crm-api", Key: "token"}}, ""},
		{"another namespace", "acme", &MCPCredential{SecretRef: SecretKeyRef{Namespace: "other", Name: "crm-api", Key: "token"}}, "own namespace"},
		{"no key", "default", &MCPCredential{SecretRef: SecretKeyRef{Name: "crm-api"}}, "secretRef.key"},
		{"no name", "default", &MCPCredential{SecretRef: SecretKeyRef{Key: "token"}}, "secretRef.name"},
		{"header with a space", "default", &MCPCredential{SecretRef: ref, Header: "X Api"}, "not an HTTP header name"},
		{"host header", "default", &MCPCredential{SecretRef: ref, Header: "Host"}, "cannot carry a credential"},
		{"cookie header", "default", &MCPCredential{SecretRef: ref, Header: "cookie"}, "cannot carry a credential"},
		{"proxy authorization", "default", &MCPCredential{SecretRef: ref, Header: "Proxy-Authorization"}, "cannot carry a credential"},
		{"scheme with a space", "default", &MCPCredential{SecretRef: ref, Scheme: "Bearer x"}, "not an auth scheme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server(tt.namespace, tt.credential).Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestMCPCredentialHeaderName(t *testing.T) {
	assert.Equal(t, "Authorization", (&MCPCredential{}).HeaderName())
	assert.Equal(t, "X-Api-Key", (&MCPCredential{Header: "X-Api-Key"}).HeaderName())
	var none *MCPCredential
	assert.Equal(t, "Authorization", none.HeaderName())
}
