package registry

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/internal/registry/authz"
	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	jwtauthn "github.com/agentregistry-dev/agentregistry/pkg/registry/auth/jwt"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

type stubAuthn struct{}

func (stubAuthn) Authenticate(context.Context, func(string) string, url.Values) (auth.Session, error) {
	return nil, auth.ErrUnauthenticated
}

func requiredAuthConfig() *config.Config {
	return &config.Config{
		AuthMode:       config.AuthModeRequired,
		AuthIssuers:    `[{"issuer":"https://idp.example.com/realms/tracefort","audiences":["agentregistry"],"jwksUri":"https://idp.example.com/realms/tracefort/protocol/openid-connect/certs"}]`,
		AuthClockSkew:  30 * time.Second,
		AuthzenURL:     "https://pdp.example.com",
		AuthzenTimeout: time.Second,
		AuthzenListMax: 100,
	}
}

func TestBuildAuthDisabledKeepsOptions(t *testing.T) {
	authzProvider := auth.NewPublicAuthzProvider()
	w, err := buildAuth(context.Background(), &config.Config{AuthMode: config.AuthModeDisabled},
		types.AppOptions{AuthnProvider: stubAuthn{}, AuthzProvider: authzProvider})
	require.NoError(t, err)

	assert.Equal(t, stubAuthn{}, w.authn)
	assert.Same(t, authzProvider, w.authz)
	assert.Nil(t, w.pdp)

	options := types.AppOptions{}
	require.NoError(t, w.applyHooks(&options, nil))
	assert.Nil(t, options.Authorizers, "disabled mode must not install hooks")
}

func TestBuildAuthRequiredBuildsProviders(t *testing.T) {
	w, err := buildAuth(context.Background(), requiredAuthConfig(), types.AppOptions{})
	require.NoError(t, err)

	assert.IsType(t, &jwtauthn.Provider{}, w.authn)
	assert.IsType(t, &authz.PEP{}, w.authz)
	require.NotNil(t, w.pdp)
	assert.Equal(t, 100, w.listMax)
}

func TestBuildAuthRequiredKeepsProvidedProviders(t *testing.T) {
	authzProvider := auth.NewPublicAuthzProvider()
	w, err := buildAuth(context.Background(), requiredAuthConfig(),
		types.AppOptions{AuthnProvider: stubAuthn{}, AuthzProvider: authzProvider})
	require.NoError(t, err)

	assert.Equal(t, stubAuthn{}, w.authn)
	assert.Same(t, authzProvider, w.authz)
	require.NotNil(t, w.pdp, "the PDP still backs the per-kind hooks")
}

func TestBuildAuthRequiredNeedsIssuersOrProvider(t *testing.T) {
	cfg := requiredAuthConfig()
	cfg.AuthIssuers = ""

	_, err := buildAuth(context.Background(), cfg, types.AppOptions{})
	require.ErrorContains(t, err, "AUTH_ISSUERS")

	w, err := buildAuth(context.Background(), cfg, types.AppOptions{AuthnProvider: stubAuthn{}})
	require.NoError(t, err, "a provider from AppOptions replaces the issuers")
	assert.Equal(t, stubAuthn{}, w.authn)
}

func TestBuildAuthRequiredRejectsBadIssuers(t *testing.T) {
	cfg := requiredAuthConfig()
	cfg.AuthIssuers = `[{"issuer":"https://idp.example.com","audiences":["agentregistry"],"algorithms":["HS256"]}]`

	_, err := buildAuth(context.Background(), cfg, types.AppOptions{})
	require.Error(t, err)
}

func TestApplyHooksCoversEveryStoreKind(t *testing.T) {
	w, err := buildAuth(context.Background(), requiredAuthConfig(), types.AppOptions{})
	require.NoError(t, err)

	stores := map[string]*v1alpha1store.Store{
		v1alpha1.KindAgent: {},
		"Widget":           {}, // an extension kind
	}
	override := func(context.Context, types.AuthorizeInput) error { return nil }
	options := types.AppOptions{Authorizers: map[string]types.Authorizer{v1alpha1.KindAgent: override}}

	require.NoError(t, w.applyHooks(&options, stores))

	for _, kind := range append([]string{"Widget"}, authz.BuiltinKinds...) {
		assert.Contains(t, options.Authorizers, kind)
		assert.Contains(t, options.ListFilters, kind)
	}
	// A hook set in AppOptions wins over the PEP's.
	assert.NoError(t, options.Authorizers[v1alpha1.KindAgent](context.Background(), types.AuthorizeInput{}),
		"override must be kept; the PEP would return 401 without a session")
}

func TestApplyHooksAnswersMe(t *testing.T) {
	w, err := buildAuth(context.Background(), requiredAuthConfig(), types.AppOptions{})
	require.NoError(t, err)
	stores := map[string]*v1alpha1store.Store{v1alpha1.KindAgent: {}}

	options := types.AppOptions{}
	require.NoError(t, w.applyHooks(&options, stores))
	require.NotNil(t, options.Permissions, "the PEP answers /v0/me")
	_, err = options.Permissions(context.Background(), "default")
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "the PEP needs a session")

	custom := func(context.Context, string) (types.Permissions, error) { return types.Permissions{Admin: true}, nil }
	options = types.AppOptions{Permissions: custom}
	require.NoError(t, w.applyHooks(&options, stores))
	got, err := options.Permissions(context.Background(), "default")
	require.NoError(t, err)
	assert.True(t, got.Admin, "a Permissions func from AppOptions wins")
}

func TestMCPResourceMetadata(t *testing.T) {
	stores := map[string]*v1alpha1store.Store{v1alpha1.KindAgent: {}}

	t.Run("published for the configured issuers", func(t *testing.T) {
		cfg := requiredAuthConfig()
		cfg.AuthMCPResource = "https://registry.example.com/mcp"
		cfg.AuthMCPScopes = []string{"registry.read"}
		w, err := buildAuth(context.Background(), cfg, types.AppOptions{})
		require.NoError(t, err)

		options := types.AppOptions{}
		require.NoError(t, w.applyHooks(&options, stores))
		require.NotNil(t, options.MCPProtectedResourceMetadata)
		meta := *options.MCPProtectedResourceMetadata
		assert.Equal(t, "https://registry.example.com/mcp", meta.Resource)
		assert.Equal(t, []string{"https://idp.example.com/realms/tracefort"}, meta.AuthorizationServers)
		assert.Equal(t, []string{"header"}, meta.BearerMethodsSupported)
		assert.Equal(t, []string{"registry.read"}, meta.ScopesSupported)
		// RFC 9728: the well-known path goes between the host and the resource's path.
		assert.Equal(t, "https://registry.example.com/.well-known/oauth-protected-resource/mcp", options.MCPResourceMetadataURL)
	})

	t.Run("resource at the root", func(t *testing.T) {
		assert.Equal(t, "https://mcp.example.com/.well-known/oauth-protected-resource",
			protectedResourceMetadataURL("https://mcp.example.com/"))
	})

	t.Run("not published without a resource URL", func(t *testing.T) {
		w, err := buildAuth(context.Background(), requiredAuthConfig(), types.AppOptions{})
		require.NoError(t, err)
		options := types.AppOptions{}
		require.NoError(t, w.applyHooks(&options, stores))
		assert.Nil(t, options.MCPProtectedResourceMetadata)
		assert.Empty(t, options.MCPResourceMetadataURL)
	})

	t.Run("metadata from AppOptions wins", func(t *testing.T) {
		cfg := requiredAuthConfig()
		cfg.AuthMCPResource = "https://registry.example.com/mcp"
		w, err := buildAuth(context.Background(), cfg, types.AppOptions{})
		require.NoError(t, err)
		own := &oauthex.ProtectedResourceMetadata{Resource: "https://own.example/mcp"}
		options := types.AppOptions{MCPProtectedResourceMetadata: own, MCPResourceMetadataURL: "https://own.example/meta"}
		require.NoError(t, w.applyHooks(&options, stores))
		assert.Same(t, own, options.MCPProtectedResourceMetadata)
		assert.Equal(t, "https://own.example/meta", options.MCPResourceMetadataURL)
	})

	t.Run("needs issuers to name", func(t *testing.T) {
		cfg := requiredAuthConfig()
		cfg.AuthIssuers = ""
		cfg.AuthMCPResource = "https://registry.example.com/mcp"
		_, err := buildAuth(context.Background(), cfg, types.AppOptions{AuthnProvider: stubAuthn{}})
		require.ErrorContains(t, err, "AUTH_MCP_RESOURCE")
	})
}

func TestPDPTokenSource(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("file-token\n"), 0o600))

	tests := []struct {
		name      string
		cfg       config.Config
		wantNil   bool
		wantToken string
		wantErr   bool
	}{
		{name: "none", wantNil: true},
		{name: "static inline", cfg: config.Config{AuthzenStaticToken: "inline"}, wantToken: "inline"},
		{name: "static file wins", cfg: config.Config{AuthzenStaticToken: "inline", AuthzenStaticTokenFile: tokenFile}, wantToken: "file-token"},
		{name: "missing static file", cfg: config.Config{AuthzenStaticTokenFile: filepath.Join(dir, "absent")}, wantErr: true},
		{name: "client credentials", cfg: config.Config{
			AuthzenTokenURL: "https://idp.example.com/token", AuthzenClientID: "agentregistry", AuthzenClientSecret: "s3cret",
		}},
		{name: "missing secret file", cfg: config.Config{
			AuthzenTokenURL: "https://idp.example.com/token", AuthzenClientID: "agentregistry",
			AuthzenClientSecretFile: filepath.Join(dir, "absent"),
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, err := pdpTokenSource(&tt.cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, ts)
				return
			}
			require.NotNil(t, ts)
			if tt.wantToken != "" {
				got, err := ts.Token(context.Background())
				require.NoError(t, err)
				assert.Equal(t, tt.wantToken, got)
				assert.IsType(t, authzen.StaticToken(""), ts)
			}
		})
	}
}
