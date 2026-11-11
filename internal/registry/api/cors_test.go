package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/internal/registry/api"
	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
)

// newTestHandler returns the middleware stack NewServer wires, around a stub
// mux that reads the body and answers 200 (or 413 when the body is over the
// limit). Lets the assertions run without a database or route registrations.
func newTestHandler(cfg *config.Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return api.Middleware(cfg, mux)
}

func TestCORS(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		origin    string
		wantAllow string
	}{
		{"auth disabled, none configured: any origin", &config.Config{}, "https://example.com", "*"},
		{"auth required, none configured: same-origin only", &config.Config{AuthMode: config.AuthModeRequired}, "https://example.com", ""},
		{"allowlisted origin", &config.Config{AuthMode: config.AuthModeRequired, CORSAllowedOrigins: []string{"https://portal.example.com"}}, "https://portal.example.com", "https://portal.example.com"},
		{"origin not on the allowlist", &config.Config{AuthMode: config.AuthModeRequired, CORSAllowedOrigins: []string{"https://portal.example.com"}}, "https://evil.example.com", ""},
		{"explicit any origin with auth", &config.Config{AuthMode: config.AuthModeRequired, CORSAllowedOrigins: []string{"*"}}, "https://example.com", "*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestHandler(tt.cfg)
			for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
				req := httptest.NewRequest(method, "/v0/mcpservers", nil)
				req.Header.Set("Origin", tt.origin)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				assert.Equal(t, tt.wantAllow, rr.Header().Get("Access-Control-Allow-Origin"), method)
			}

			req := httptest.NewRequest(http.MethodOptions, "/v0/mcpservers", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
			req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tt.wantAllow, rr.Header().Get("Access-Control-Allow-Origin"), "preflight")
			if tt.wantAllow != "" {
				assert.Contains(t, rr.Header().Get("Access-Control-Allow-Methods"), http.MethodPost)
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Credentials"), "bearer tokens, never cookies")
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		wantHSTS string
	}{
		{"without HSTS", &config.Config{}, ""},
		{"with HSTS", &config.Config{HTTPHSTSMaxAge: 365 * 24 * time.Hour}, "max-age=31536000; includeSubDomains"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestHandler(tt.cfg)
			// Every response, including redirects, carries the headers.
			for _, path := range []string{"/v0/agents", "/v0/agents/"} {
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
				h := rr.Header()
				assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), path)
				assert.Equal(t, "DENY", h.Get("X-Frame-Options"), path)
				assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"), path)
				assert.Equal(t, "same-origin", h.Get("Cross-Origin-Opener-Policy"), path)
				assert.Equal(t, tt.wantHSTS, h.Get("Strict-Transport-Security"), path)
			}
		})
	}
}

func TestBodyLimit(t *testing.T) {
	limited := newTestHandler(&config.Config{HTTPMaxBodyBytes: 10})
	unlimited := newTestHandler(&config.Config{})

	tests := []struct {
		name    string
		handler http.Handler
		body    string
		chunked bool
		want    int
	}{
		{"within the limit", limited, "0123456789", false, http.StatusOK},
		{"over the limit by Content-Length", limited, "0123456789x", false, http.StatusRequestEntityTooLarge},
		{"over the limit without Content-Length", limited, "0123456789x", true, http.StatusRequestEntityTooLarge},
		{"zero means no limit", unlimited, strings.Repeat("x", 1<<20), false, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v0/apply", strings.NewReader(tt.body))
			if tt.chunked {
				req.ContentLength = -1
			}
			rr := httptest.NewRecorder()
			tt.handler.ServeHTTP(rr, req)
			require.Equal(t, tt.want, rr.Code)
		})
	}
}
