package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1/registries"
	"github.com/agentregistry-dev/agentregistry/pkg/secret"
)

// fakeResolver returns data for one Secret.
type fakeResolver struct {
	ref  v1alpha1.SecretRef
	data map[string]string
	err  error
	got  []v1alpha1.SecretRef
}

func (f *fakeResolver) Resolve(context.Context, v1alpha1.SecretRef) (secret.SensitiveValue, error) {
	return secret.SensitiveValue{}, errors.New("not used")
}

func (f *fakeResolver) ResolveAll(_ context.Context, ref v1alpha1.SecretRef) (map[string]secret.SensitiveValue, error) {
	f.got = append(f.got, ref)
	if f.err != nil {
		return nil, f.err
	}
	if ref != f.ref {
		return nil, secret.ErrNotFound
	}
	out := make(map[string]secret.SensitiveValue, len(f.data))
	for k, v := range f.data {
		out[k] = secret.NewSensitiveValue([]byte(v))
	}
	return out, nil
}

func TestBuildRegistryValidator(t *testing.T) {
	resolver := &fakeResolver{}
	tests := []struct {
		name     string
		cfg      config.Config
		resolver secret.Resolver
		wantNil  bool
		wantErr  string
	}{
		{name: "no registries keeps the default", resolver: resolver, wantNil: true},
		{name: "registries listed", cfg: config.Config{OCIRegistries: `[{"host":"harbor.example.com","credentialsSecret":"harbor-pull"}]`}, resolver: resolver},
		{name: "anonymous registry needs no secret store", cfg: config.Config{OCIRegistries: `[{"host":"harbor.example.com"}]`}},
		{name: "invalid JSON", cfg: config.Config{OCIRegistries: `[{"host":`}, resolver: resolver, wantErr: "OCI_REGISTRIES"},
		{name: "credentials without a secret store", cfg: config.Config{OCIRegistries: `[{"host":"harbor.example.com","credentialsSecret":"harbor-pull"}]`},
			wantErr: "no secret store"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRegistryValidator(&tt.cfg, tt.resolver)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantNil, got == nil)
		})
	}
}

func TestOCICredentials(t *testing.T) {
	harbor := registries.TrustedOCIRegistry{Host: "harbor.example.com", CredentialsSecret: "platform/harbor-pull"}
	ref := v1alpha1.SecretRef{Namespace: "platform", Name: "harbor-pull"}

	t.Run("reads username and password from the Secret", func(t *testing.T) {
		resolver := &fakeResolver{ref: ref, data: map[string]string{"username": "robot$mcp ", "password": " s3cret\n"}}
		auth, err := ociCredentials(resolver)(context.Background(), harbor)
		require.NoError(t, err)
		cfg, err := auth.Authorization()
		require.NoError(t, err)
		assert.Equal(t, &authn.AuthConfig{Username: "robot$mcp", Password: "s3cret"}, cfg)
	})
	t.Run("reads the Secret on every call", func(t *testing.T) {
		resolver := &fakeResolver{ref: ref, data: map[string]string{"username": "u", "password": "p"}}
		creds := ociCredentials(resolver)
		_, _ = creds(context.Background(), harbor)
		_, _ = creds(context.Background(), harbor)
		assert.Len(t, resolver.got, 2)
	})
	t.Run("a bare name is in the default namespace", func(t *testing.T) {
		resolver := &fakeResolver{ref: v1alpha1.SecretRef{Namespace: v1alpha1.DefaultNamespace, Name: "harbor-pull"},
			data: map[string]string{"username": "u", "password": "p"}}
		_, err := ociCredentials(resolver)(context.Background(), registries.TrustedOCIRegistry{Host: "harbor.example.com", CredentialsSecret: "harbor-pull"})
		require.NoError(t, err)
	})
	for _, tt := range []struct {
		name    string
		data    map[string]string
		err     error
		wantErr string
	}{
		{name: "no password", data: map[string]string{"username": "u"}, wantErr: `needs both "username" and "password"`},
		{name: "no username", data: map[string]string{"password": "p"}, wantErr: `needs both "username" and "password"`},
		{name: "the Secret can't be read", err: secret.ErrNotFound, wantErr: secret.ErrNotFound.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeResolver{ref: ref, data: tt.data, err: tt.err}
			_, err := ociCredentials(resolver)(context.Background(), harbor)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
