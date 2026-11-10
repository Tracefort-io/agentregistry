package registry

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

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
