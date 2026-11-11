package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
)

// testUIFS simulates the Next.js static export layout:
//   - index.html         root page
//   - deployed.html      page route (Next.js writes /deployed -> deployed.html)
//   - deployed/          directory of internal Next.js route metadata files
//   - _next/static/...   hashed asset files
var testUIFS = fstest.MapFS{
	"index.html":                    {Data: []byte("<html>index</html>")},
	"deployed.html":                 {Data: []byte("<html>deployed</html>")},
	"deployed/__next._full.txt":     {Data: []byte("internal")},
	"deployed/__next._index.txt":    {Data: []byte("internal")},
	"_next/static/chunk.abc123.js":  {Data: []byte("console.log('chunk')")},
	"_next/static/style.abc123.css": {Data: []byte("body{}")},
}

func TestNewUIHandler(t *testing.T) {
	handler, err := newUIHandler(testUIFS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name             string
		path             string
		wantStatus       int
		wantBodyContains string
	}{
		{
			name:             "root serves index.html",
			path:             "/",
			wantStatus:       http.StatusOK,
			wantBodyContains: "<html>index</html>",
		},
		{
			name:             "page route maps to .html file",
			path:             "/deployed",
			wantStatus:       http.StatusOK,
			wantBodyContains: "<html>deployed</html>",
		},
		{
			name:             "trailing slash on page route resolves same as without",
			path:             "/deployed/",
			wantStatus:       http.StatusOK,
			wantBodyContains: "<html>deployed</html>",
		},
		{
			name:             "existing static asset served directly",
			path:             "/_next/static/chunk.abc123.js",
			wantStatus:       http.StatusOK,
			wantBodyContains: "console.log('chunk')",
		},
		{
			name:       "missing asset with extension returns 404",
			path:       "/missing.js",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "missing asset in subdirectory returns 404",
			path:       "/_next/static/missing.css",
			wantStatus: http.StatusNotFound,
		},
		{
			name:             "unknown route without extension falls back to index.html",
			path:             "/unknown-page",
			wantStatus:       http.StatusOK,
			wantBodyContains: "<html>index</html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantBodyContains != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.wantBodyContains) {
					t.Errorf("body %q does not contain %q", body, tt.wantBodyContains)
				}
			}
		})
	}
}

func TestUIContentSecurityPolicy(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		want     []string
		wantNone []string
	}{
		{
			name:     "without sign-in",
			cfg:      &config.Config{},
			want:     []string{"default-src 'self'", "connect-src 'self';", "frame-ancestors 'none'", "object-src 'none'"},
			wantNone: []string{"http:", "https:", "*"},
		},
		{
			name: "allows the sign-in service's origin, not its path",
			cfg:  &config.Config{AuthUIIssuer: "https://idp.example.com/realms/tracefort"},
			want: []string{
				"connect-src 'self' https://idp.example.com;",
				"frame-src 'self' https://idp.example.com;",
				"form-action 'self' https://idp.example.com;",
			},
			wantNone: []string{"/realms"},
		},
		{
			name:     "replaced by HTTP_CSP",
			cfg:      &config.Config{AuthUIIssuer: "https://idp.example.com/realms/r", HTTPCSP: "default-src 'none'"},
			want:     []string{"default-src 'none'"},
			wantNone: []string{"idp.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := newUIHandler(testUIFS)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			withUIContentSecurityPolicy(uiContentSecurityPolicy(tt.cfg), h).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/deployed", nil))
			got := rr.Header().Get("Content-Security-Policy") + ";"
			for _, s := range tt.want {
				if !strings.Contains(got, s) {
					t.Errorf("policy %q lacks %q", got, s)
				}
			}
			for _, s := range tt.wantNone {
				if strings.Contains(got, s) {
					t.Errorf("policy %q must not contain %q", got, s)
				}
			}
		})
	}
}
