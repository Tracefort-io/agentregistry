package router

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

var logger = logging.New("router")

// apiPathPrefix is the version prefix every registry operation lives under.
const apiPathPrefix = "/v0"

// legacyAuthnSkipPaths are served without authentication when auth is not
// required. Like configured open paths they are matched exactly, each also
// under /v0.
var legacyAuthnSkipPaths = []string{"/health", "/metrics", "/ping", "/docs", "/version"}

// openPathSet expands open paths into the exact request paths served without
// authentication. Each path is open as given and under the API prefix, so
// "/health" also opens "/v0/health". It returns nil when the list is empty.
func openPathSet(paths []string) map[string]bool {
	var open map[string]bool
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") || p == "/" {
			logger.Warn("ignoring invalid auth open path", "path", p)
			continue
		}
		if open == nil {
			open = make(map[string]bool)
		}
		open[p] = true
		if p != apiPathPrefix && !strings.HasPrefix(p, apiPathPrefix+"/") {
			open[apiPathPrefix+p] = true
		}
	}
	return open
}

// authnHumaMiddleware authenticates every huma operation except the exact
// open paths. Open paths are matched here rather than passed to
// auth.WithSkipPaths, whose last-segment matching would also open e.g.
// /v0/agents/health.
func authnHumaMiddleware(provider auth.AuthnProvider, open map[string]bool, opts ...auth.MiddlewareOption) func(huma.Context, func(huma.Context)) {
	authn := auth.AuthnMiddleware(provider, opts...)
	return func(ctx huma.Context, next func(huma.Context)) {
		if open[ctx.URL().Path] {
			next(ctx)
			return
		}
		authn(ctx, next)
	}
}

// requestIDHeader correlates registry logs with PDP decision logs.
const requestIDHeader = "X-Request-ID"

// maxRequestIDLength bounds a caller-supplied request ID before it reaches
// logs and the PDP.
const maxRequestIDLength = 128

// requestIDMiddleware puts the caller's X-Request-ID, or a generated one,
// into the request context for AuthZEN calls and echoes it on the response.
func requestIDMiddleware(ctx huma.Context, next func(huma.Context)) {
	id := strings.TrimSpace(ctx.Header(requestIDHeader))
	if id == "" || len(id) > maxRequestIDLength {
		id = newRequestID()
	}
	ctx.SetHeader(requestIDHeader, id)
	next(huma.WithContext(ctx, authzen.WithRequestID(ctx.Context(), id)))
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// requireAuthn guards plain HTTP handlers that bypass the huma middleware
// chain (OpenAPI documents, docs, schemas, metrics).
func requireAuthn(provider auth.AuthnProvider, open map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if open[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			session, err := provider.Authenticate(r.Context(), r.Header.Get, r.URL.Query())
			if err != nil {
				logger.Warn("authentication failed", "path", r.URL.Path, "error", err)
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if session != nil {
				r = r.WithContext(auth.AuthSessionTo(r.Context(), session))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// guardedMux wraps handlers registered while wrap is set. huma registers its
// built-in OpenAPI, docs and schema routes directly on the mux when the API
// is created, outside the middleware chain; NewHumaAPI sets wrap for that
// window only, so operations registered later are not authenticated twice.
type guardedMux struct {
	*http.ServeMux
	wrap func(http.Handler) http.Handler
}

var _ humago.Mux = (*guardedMux)(nil)

func (m *guardedMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	if m.wrap == nil {
		m.ServeMux.HandleFunc(pattern, handler)
		return
	}
	m.ServeMux.Handle(pattern, m.wrap(http.HandlerFunc(handler)))
}
