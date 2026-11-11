package router

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
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

// authConfig tells the web UI whether to sign users in, and where. The UI is a
// static export, so it reads these at runtime instead of at build time.
type authConfig struct {
	Required bool   `json:"required"`
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"clientId,omitempty"`
	Scopes   string `json:"scopes,omitempty"`
}

// authConfigHandler serves /auth-config.json. Sign-in details are included
// only when auth is required; a public client ID and an issuer URL are not
// secrets.
func authConfigHandler(cfg *config.Config) http.Handler {
	body := authConfig{Required: cfg.AuthMode == config.AuthModeRequired}
	if body.Required {
		body.Issuer, body.ClientID = cfg.AuthUIIssuer, cfg.AuthUIClientID
		if body.ClientID != "" {
			body.Scopes = cfg.AuthUIScopes
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		// A struct of strings and a bool always encodes.
		panic(fmt.Sprintf("encode auth config: %v", err))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	})
}

// requestIDHeader correlates registry logs with PDP decision logs.
const requestIDHeader = "X-Request-ID"

// maxRequestIDLength bounds a caller-supplied request ID before it reaches
// logs and the PDP.
const maxRequestIDLength = 128

// requestIDMiddleware puts the caller's X-Request-ID, or a generated one,
// into the request context for AuthZEN calls and echoes it on the response.
// It also gives the request its own AuthZEN decision memo, so a question
// asked twice while serving it (such as the list check made by both the
// handler and its list filter) reaches the PDP once.
func requestIDMiddleware(ctx huma.Context, next func(huma.Context)) {
	id := strings.TrimSpace(ctx.Header(requestIDHeader))
	if id == "" || len(id) > maxRequestIDLength {
		id = newRequestID()
	}
	ctx.SetHeader(requestIDHeader, id)
	reqCtx := authzen.WithDecisionMemo(authzen.WithRequestID(ctx.Context(), id))
	next(huma.WithContext(ctx, reqCtx))
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// skipPathsOption opens the exact paths of an open path set.
func skipPathsOption(open map[string]bool) auth.MiddlewareOption {
	return auth.WithSkipPaths(slices.Sorted(maps.Keys(open))...)
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
	m.Handle(pattern, m.wrap(http.HandlerFunc(handler)))
}
