package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/internal/registry/telemetry"
	arv0 "github.com/agentregistry-dev/agentregistry/pkg/api/v0"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

type rejectingAuthnProvider struct {
	calls int
}

func (p *rejectingAuthnProvider) Authenticate(context.Context, func(string) string, url.Values) (auth.Session, error) {
	p.calls++
	return nil, auth.ErrUnauthenticated
}

func TestNewHumaAPIAuthenticationBoundaries(t *testing.T) {
	metrics, err := telemetry.NewMetrics(otel.GetMeterProvider().Meter("router-test"))
	require.NoError(t, err)

	mux := http.NewServeMux()
	provider := &rejectingAuthnProvider{}
	_, err = NewHumaAPI(
		&config.Config{PluginMarketplaceCompatEnabled: true},
		mux,
		metrics,
		&arv0.VersionBody{},
		nil,
		provider,
		&RouteOptions{Stores: Stores{v1alpha1.KindPlugin: &v1alpha1store.Store{}}},
		nil,
	)
	require.NoError(t, err)

	t.Run("marketplace uses configured authentication", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/plugin-marketplace/marketplace.json", nil))

		require.Equal(t, http.StatusUnauthorized, recorder.Code)
		require.Equal(t, 1, provider.calls)
	})

	t.Run("skip route remains unauthenticated", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v0/ping", nil))

		require.Equal(t, http.StatusOK, recorder.Code)
		require.Equal(t, 1, provider.calls)
	})
}

// tokenAuthnProvider accepts only "Bearer ok".
type tokenAuthnProvider struct{}

type okSession struct{}

func (okSession) Principal() auth.Principal { return auth.Principal{Subject: "s", Issuer: "i"} }

func (tokenAuthnProvider) Authenticate(_ context.Context, header func(string) string, _ url.Values) (auth.Session, error) {
	if header("Authorization") == "Bearer ok" {
		return okSession{}, nil
	}
	return nil, auth.ErrUnauthenticated
}

func newTestAPI(t *testing.T, cfg *config.Config, provider auth.AuthnProvider) *http.ServeMux {
	t.Helper()
	metrics, err := telemetry.NewMetrics(otel.GetMeterProvider().Meter("router-test"))
	require.NoError(t, err)
	mux := http.NewServeMux()
	_, err = NewHumaAPI(cfg, mux, metrics, &arv0.VersionBody{}, nil, provider,
		&RouteOptions{
			Stores: Stores{v1alpha1.KindPlugin: &v1alpha1store.Store{}},
			ExtraRoutes: func(api huma.API, pathPrefix string) {
				huma.Get(api, pathPrefix+"/things/{name}", func(context.Context, *struct {
					Name string `path:"name"`
				}) (*struct{}, error) {
					return &struct{}{}, nil
				})
			},
		},
		nil,
	)
	require.NoError(t, err)
	return mux
}

func TestNewHumaAPIOpenPaths(t *testing.T) {
	mux := newTestAPI(t, &config.Config{AuthMode: config.AuthModeRequired, AuthOpenPaths: []string{"/health", "/ping", "/version"}}, tokenAuthnProvider{})

	tests := []struct {
		path       string
		token      bool
		wantStatus int
	}{
		{"/v0/health", false, http.StatusOK},
		{"/v0/ping", false, http.StatusOK},
		{"/v0/version", false, http.StatusOK},
		{"/v0/things/x", false, http.StatusUnauthorized},
		{"/v0/things/x", true, http.StatusNoContent},
		// Exact matching: a resource named like an open path is not open.
		{"/v0/things/health", false, http.StatusUnauthorized},
		{"/v0/things/version", false, http.StatusUnauthorized},
		{"/docs", false, http.StatusUnauthorized},
		{"/docs", true, http.StatusOK},
		{"/openapi.json", false, http.StatusUnauthorized},
		{"/openapi.yaml", false, http.StatusUnauthorized},
		{"/openapi.json", true, http.StatusOK},
		{"/metrics", false, http.StatusUnauthorized},
		{"/metrics", true, http.StatusOK},
	}
	for _, tt := range tests {
		name := tt.path
		if tt.token {
			name += " with token"
		}
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.token {
				req.Header.Set("Authorization", "Bearer ok")
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			require.Equal(t, tt.wantStatus, recorder.Code)
		})
	}
}

func TestNewHumaAPIOpenPathsCanOpenDocsAndMetrics(t *testing.T) {
	mux := newTestAPI(t, &config.Config{AuthMode: config.AuthModeRequired, AuthOpenPaths: []string{"/docs", "/metrics"}}, tokenAuthnProvider{})
	for _, tt := range []struct {
		path       string
		wantStatus int
	}{
		{"/docs", http.StatusOK},
		{"/metrics", http.StatusOK},
		{"/v0/health", http.StatusUnauthorized},
		{"/openapi.json", http.StatusUnauthorized},
	} {
		t.Run(tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
			require.Equal(t, tt.wantStatus, recorder.Code)
		})
	}
}

// Without AuthMode "required" the legacy skip list applies, matched exactly:
// docs and /metrics stay open, but a resource named after a skip path does not.
func TestNewHumaAPILegacySkipPathsMatchExactly(t *testing.T) {
	mux := newTestAPI(t, &config.Config{AuthOpenPaths: []string{"/health"}}, tokenAuthnProvider{})
	for _, tt := range []struct {
		path       string
		wantStatus int
	}{
		{"/v0/health", http.StatusOK},
		{"/v0/ping", http.StatusOK},
		{"/docs", http.StatusOK},
		{"/metrics", http.StatusOK},
		{"/v0/things/x", http.StatusUnauthorized},
		{"/v0/things/health", http.StatusUnauthorized},
		{"/v0/things/metrics", http.StatusUnauthorized},
	} {
		t.Run(tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
			require.Equal(t, tt.wantStatus, recorder.Code)
		})
	}
}

func TestNewHumaAPIWithoutAuthnIgnoresOpenPaths(t *testing.T) {
	mux := newTestAPI(t, &config.Config{AuthOpenPaths: []string{"/health"}}, nil)
	for _, path := range []string{"/docs", "/openapi.json", "/metrics", "/v0/things/x"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		require.Less(t, recorder.Code, 400, path)
	}
}

func TestOpenPathSet(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  map[string]bool
	}{
		{"nil", nil, nil},
		{"only blanks", []string{"", " "}, nil},
		{"invalid entries dropped", []string{"health", "/"}, nil},
		{
			"expanded under api prefix",
			[]string{"/health", " /ping "},
			map[string]bool{"/health": true, "/v0/health": true, "/ping": true, "/v0/ping": true},
		},
		{"already prefixed", []string{"/v0/health"}, map[string]bool{"/v0/health": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, openPathSet(tt.paths))
		})
	}
}

func TestNewHumaAPIRequestID(t *testing.T) {
	mux := newTestAPI(t, &config.Config{}, nil)

	t.Run("caller id is echoed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v0/things/x", nil)
		req.Header.Set("X-Request-ID", "req-123")
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		require.Equal(t, "req-123", recorder.Header().Get("X-Request-ID"))
	})
	t.Run("missing id is generated", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v0/things/x", nil))
		require.Len(t, recorder.Header().Get("X-Request-ID"), 32)
	})
}

// With auth required, /logging needs a token even from localhost: behind a
// same-pod proxy every request arrives from 127.0.0.1.
func TestNewHumaAPILoggingRequiresAuthn(t *testing.T) {
	mux := newTestAPI(t, &config.Config{AuthMode: config.AuthModeRequired, AuthOpenPaths: []string{"/health"}}, tokenAuthnProvider{})
	for _, tt := range []struct {
		name       string
		token      bool
		wantStatus int
	}{
		{"without token", false, http.StatusUnauthorized},
		{"with token", true, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/logging", nil)
			req.RemoteAddr = "127.0.0.1:41000"
			if tt.token {
				req.Header.Set("Authorization", "Bearer ok")
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			require.Equal(t, tt.wantStatus, recorder.Code)
		})
	}
}
