package registries

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

const (
	testUser     = "robot$mcp-pull"
	testPassword = "pull-secret"
)

// privateRegistry is an in-process OCI registry that requires basic auth.
// It returns the registry's host and pushes images with the given label.
func privateRegistry(t *testing.T) (host string, push func(repoTag string, labels map[string]string)) {
	t.Helper()
	inner := ggcrregistry.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != testUser || p != testPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	host = strings.TrimPrefix(srv.URL, "http://")
	return host, func(repoTag string, labels map[string]string) {
		t.Helper()
		img, err := random.Image(256, 1)
		require.NoError(t, err)
		cfg, err := img.ConfigFile()
		require.NoError(t, err)
		cfg.Config.Labels = labels
		img, err = mutate.ConfigFile(img, cfg)
		require.NoError(t, err)
		ref, err := name.ParseReference(host + "/" + repoTag)
		require.NoError(t, err)
		require.NoError(t, remote.Write(ref, img, remote.WithAuth(&authn.Basic{Username: testUser, Password: testPassword})))
	}
}

func oci(identifier string) v1alpha1.MCPPackageOrigin {
	return v1alpha1.MCPPackageOrigin{Type: v1alpha1.MCPPackageOriginTypeOCI, Identifier: identifier, OCI: &v1alpha1.MCPPackageOriginOCI{}}
}

func TestNewDispatcherTrustedRegistry(t *testing.T) {
	host, push := privateRegistry(t)
	push("team/weather:1.0.0", map[string]string{"io.modelcontextprotocol.server.name": "io.example/weather"})
	push("team/unlabelled:1.0.0", nil)

	trusted := []TrustedOCIRegistry{{Host: host, CredentialsSecret: "default/registry-pull"}}
	goodCredentials := func(_ context.Context, r TrustedOCIRegistry) (authn.Authenticator, error) {
		assert.Equal(t, "default/registry-pull", r.CredentialsSecret)
		return &authn.Basic{Username: testUser, Password: testPassword}, nil
	}

	tests := []struct {
		name        string
		identifier  string
		serverName  string
		credentials OCICredentialsFunc
		wantErr     string
	}{
		{name: "matching label with the registry's credentials", identifier: host + "/team/weather:1.0.0",
			serverName: "io.example/weather", credentials: goodCredentials},
		{name: "wrong credentials", identifier: host + "/team/weather:1.0.0", serverName: "io.example/weather",
			credentials: func(context.Context, TrustedOCIRegistry) (authn.Authenticator, error) {
				return &authn.Basic{Username: testUser, Password: "wrong"}, nil
			},
			wantErr: "refused to read"},
		{name: "credentials can't be read", identifier: host + "/team/weather:1.0.0", serverName: "io.example/weather",
			credentials: func(context.Context, TrustedOCIRegistry) (authn.Authenticator, error) {
				return nil, errors.New("secret not found")
			},
			wantErr: "credentials default/registry-pull: secret not found"},
		{name: "label names another server", identifier: host + "/team/weather:1.0.0", serverName: "io.example/other",
			credentials: goodCredentials, wantErr: "ownership validation failed"},
		{name: "no label", identifier: host + "/team/unlabelled:1.0.0", serverName: "io.example/weather",
			credentials: goodCredentials, wantErr: "missing required annotation"},
		{name: "no such image", identifier: host + "/team/missing:1.0.0", serverName: "io.example/weather",
			credentials: goodCredentials, wantErr: "does not exist"},
		{name: "no tag or digest", identifier: host + "/team/weather", serverName: "io.example/weather",
			credentials: goodCredentials, wantErr: "explicit tag"},
		{name: "a registry that is not trusted keeps the public rules", identifier: "quay.io/team/weather:1.0.0",
			serverName: "io.example/weather", credentials: goodCredentials, wantErr: "unsupported OCI registry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewDispatcher(trusted, tt.credentials)(context.Background(), oci(tt.identifier), tt.serverName)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestNewDispatcherTrustedRegistryWithoutCredentials(t *testing.T) {
	host, push := privateRegistry(t)
	push("team/weather:1.0.0", map[string]string{"io.modelcontextprotocol.server.name": "io.example/weather"})

	// Anonymous reads of a registry that requires a login are refused.
	err := NewDispatcher([]TrustedOCIRegistry{{Host: host}}, nil)(context.Background(), oci(host+"/team/weather:1.0.0"), "io.example/weather")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "(anonymous)")

	// A registry that names a Secret needs a way to read it.
	err = NewDispatcher([]TrustedOCIRegistry{{Host: host, CredentialsSecret: "pull"}}, nil)(context.Background(), oci(host+"/team/weather:1.0.0"), "io.example/weather")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no way to read its credentials")
}

func TestTrustedReferenceScheme(t *testing.T) {
	for _, tt := range []struct {
		insecure bool
		want     string
	}{{false, "https"}, {true, "http"}} {
		ref, err := trustedReference(TrustedOCIRegistry{Host: "registry.example.com", Insecure: tt.insecure}, "registry.example.com/team/weather:1.0.0")
		require.NoError(t, err)
		assert.Equal(t, tt.want, ref.Context().Scheme(), "insecure=%v", tt.insecure)
	}
}

func TestLoadTrustedOCIRegistries(t *testing.T) {
	tests := []struct {
		name    string
		inline  string
		want    []TrustedOCIRegistry
		wantErr string
	}{
		{name: "none", inline: "  "},
		{name: "valid", inline: `[{"host":"Harbor.Example.com:8443","credentialsSecret":"platform/harbor-pull","insecure":true},{"host":"10.0.0.5"}]`,
			want: []TrustedOCIRegistry{{Host: "harbor.example.com:8443", CredentialsSecret: "platform/harbor-pull", Insecure: true}, {Host: "10.0.0.5"}}},
		{name: "bracketed IPv6 with port", inline: `[{"host":"[fd00::1]:5000"}]`, want: []TrustedOCIRegistry{{Host: "[fd00::1]:5000"}}},
		{name: "scheme", inline: `[{"host":"https://harbor.example.com"}]`, wantErr: "without a scheme or path"},
		{name: "path", inline: `[{"host":"harbor.example.com/library"}]`, wantErr: "without a scheme or path"},
		{name: "empty host", inline: `[{"host":""}]`, wantErr: "without a scheme or path"},
		{name: "listed twice", inline: `[{"host":"harbor.example.com"},{"host":"HARBOR.example.com"}]`, wantErr: "listed twice"},
		{name: "bad secret reference", inline: `[{"host":"harbor.example.com","credentialsSecret":"a/b/c"}]`, wantErr: "credentialsSecret"},
		{name: "unknown field", inline: `[{"host":"harbor.example.com","password":"x"}]`, wantErr: "unknown field"},
		{name: "not an array", inline: `{"host":"harbor.example.com"}`, wantErr: "parsing OCI registries"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadTrustedOCIRegistries(tt.inline, "")
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadTrustedOCIRegistriesFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "registries.json")
	require.NoError(t, os.WriteFile(file, []byte(`[{"host":"harbor.example.com"}]`), 0o600))

	got, err := LoadTrustedOCIRegistries(`[{"host":"ignored.example.com"}]`, file)
	require.NoError(t, err)
	assert.Equal(t, []TrustedOCIRegistry{{Host: "harbor.example.com"}}, got, "the file wins over the inline value")

	_, err = LoadTrustedOCIRegistries("", filepath.Join(t.TempDir(), "missing.json"))
	assert.Error(t, err)
}

func TestSecretName(t *testing.T) {
	for _, tt := range []struct {
		ref, wantNS, wantName string
		wantErr               bool
	}{
		{"harbor-pull", "default", "harbor-pull", false},
		{"platform/harbor-pull", "platform", "harbor-pull", false},
		{"/harbor-pull", "", "", true},
		{"platform/", "", "", true},
		{"a/b/c", "", "", true},
	} {
		ns, n, err := SecretName(tt.ref)
		if tt.wantErr {
			require.Error(t, err, tt.ref)
			continue
		}
		require.NoError(t, err, tt.ref)
		assert.Equal(t, tt.wantNS, ns, tt.ref)
		assert.Equal(t, tt.wantName, n, tt.ref)
	}
}
