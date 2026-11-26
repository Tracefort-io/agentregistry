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
		{"explicit static", "default", &MCPCredential{Type: MCPCredentialTypeStatic, SecretRef: ref}, ""},
		{"unknown type", "default", &MCPCredential{Type: "ApiKey", SecretRef: ref}, "spec.credential.type"},
		{"static with oauth settings", "default", &MCPCredential{SecretRef: ref, OAuthClientCredentials: &MCPOAuthClientCredentials{}}, "only for type"},

		{"oauth", "default", oauth(nil), ""},
		{"oauth with scopes and resource", "acme", oauth(func(o *MCPOAuthClientCredentials) {
			o.Scopes = []string{"crm:read", "crm:write"}
			o.Resource = "https://crm.example.com/mcp"
		}), ""},
		{"oauth token URL with a query", "default", oauth(func(o *MCPOAuthClientCredentials) { o.TokenURL = "https://auth.example.com/token?tenant=a" }), ""},
		{"oauth without settings", "default", &MCPCredential{Type: MCPCredentialTypeOAuthClientCredentials, SecretRef: SecretKeyRef{Name: "crm-client"}}, "oauthClientCredentials"},
		{"oauth with secretRef.key", "default", withCredential(oauth(nil), func(c *MCPCredential) { c.SecretRef.Key = "token" }), "secretRef.key"},
		{"oauth with header", "default", withCredential(oauth(nil), func(c *MCPCredential) { c.Header = "X-Api-Key" }), "fixed to Authorization: Bearer"},
		{"oauth with scheme", "default", withCredential(oauth(nil), func(c *MCPCredential) { c.Scheme = "Bearer" }), "fixed to Authorization: Bearer"},
		{"oauth in another namespace", "acme", withCredential(oauth(nil), func(c *MCPCredential) { c.SecretRef.Namespace = "other" }), "own namespace"},
		{"oauth no token URL", "default", oauth(func(o *MCPOAuthClientCredentials) { o.TokenURL = "" }), "tokenUrl"},
		{"oauth http token URL", "default", oauth(func(o *MCPOAuthClientCredentials) { o.TokenURL = "http://auth.example.com/token" }), "https URL"},
		{"oauth relative token URL", "default", oauth(func(o *MCPOAuthClientCredentials) { o.TokenURL = "/token" }), "https URL"},
		{"oauth token URL with user info", "default", oauth(func(o *MCPOAuthClientCredentials) { o.TokenURL = "https://u:p@auth.example.com/token" }), "user info"},
		{"oauth token URL with a fragment", "default", oauth(func(o *MCPOAuthClientCredentials) { o.TokenURL = "https://auth.example.com/token#x" }), "fragment"},
		{"oauth no client id key", "default", oauth(func(o *MCPOAuthClientCredentials) { o.ClientIDKey = "" }), "clientIdKey"},
		{"oauth bad client secret key", "default", oauth(func(o *MCPOAuthClientCredentials) { o.ClientSecretKey = "client/secret" }), "not a Secret key"},
		{"oauth same keys", "default", oauth(func(o *MCPOAuthClientCredentials) { o.ClientSecretKey = o.ClientIDKey }), "must differ"},
		{"oauth scope with a space", "default", oauth(func(o *MCPOAuthClientCredentials) { o.Scopes = []string{"crm read"} }), "not an OAuth scope"},
		{"oauth scope with a quote", "default", oauth(func(o *MCPOAuthClientCredentials) { o.Scopes = []string{`crm"`} }), "not an OAuth scope"},
		{"oauth empty scope", "default", oauth(func(o *MCPOAuthClientCredentials) { o.Scopes = []string{""} }), "not an OAuth scope"},
		{"oauth repeated scope", "default", oauth(func(o *MCPOAuthClientCredentials) { o.Scopes = []string{"a", "a"} }), "repeated"},
		{"oauth relative resource", "default", oauth(func(o *MCPOAuthClientCredentials) { o.Resource = "crm.example.com" }), "absolute URI"},
		{"oauth resource with a fragment", "default", oauth(func(o *MCPOAuthClientCredentials) { o.Resource = "https://crm.example.com/mcp#a" }), "fragment"},
		{"oauth resource with a query", "default", oauth(func(o *MCPOAuthClientCredentials) { o.Resource = "https://crm.example.com/mcp?a=b" }), "query"},
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

// oauth is a valid OAuth client credential, changed by mutate when set.
func oauth(mutate func(*MCPOAuthClientCredentials)) *MCPCredential {
	o := &MCPOAuthClientCredentials{
		TokenURL: "https://auth.example.com/token", ClientIDKey: "client-id", ClientSecretKey: "client-secret",
	}
	if mutate != nil {
		mutate(o)
	}
	return &MCPCredential{Type: MCPCredentialTypeOAuthClientCredentials, SecretRef: SecretKeyRef{Name: "crm-client"}, OAuthClientCredentials: o}
}

func withCredential(c *MCPCredential, mutate func(*MCPCredential)) *MCPCredential {
	mutate(c)
	return c
}

func TestMCPCredentialHeaderName(t *testing.T) {
	assert.Equal(t, "Authorization", (&MCPCredential{}).HeaderName())
	assert.Equal(t, "X-Api-Key", (&MCPCredential{Header: "X-Api-Key"}).HeaderName())
	var none *MCPCredential
	assert.Equal(t, "Authorization", none.HeaderName())
	assert.Equal(t, "Authorization", (&MCPCredential{Type: MCPCredentialTypeOAuthClientCredentials, Header: "X-Api-Key"}).HeaderName())
}

func TestMCPCredentialType(t *testing.T) {
	var none *MCPCredential
	assert.Equal(t, MCPCredentialTypeStatic, none.CredentialType())
	assert.Equal(t, MCPCredentialTypeStatic, (&MCPCredential{}).CredentialType())
	assert.Equal(t, MCPCredentialTypeOAuthClientCredentials, oauth(nil).CredentialType())
}
