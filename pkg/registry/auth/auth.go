package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// PermissionArtifactType represents the type of artifact that a permission is for.
type PermissionArtifactType string

const (
	PermissionArtifactTypeAgent   PermissionArtifactType = "agent"
	PermissionArtifactTypeSkill   PermissionArtifactType = "skill"
	PermissionArtifactTypeServer  PermissionArtifactType = "server"
	PermissionArtifactTypePrompt  PermissionArtifactType = "prompt"
	PermissionArtifactTypeRuntime PermissionArtifactType = "runtime"
)

// PermissionAction represents an action that can be performed on a resource.
type PermissionAction string

const (
	PermissionActionRead    PermissionAction = "read"
	PermissionActionPublish PermissionAction = "publish"
	PermissionActionEdit    PermissionAction = "edit"
	PermissionActionDelete  PermissionAction = "delete"
	PermissionActionDeploy  PermissionAction = "deploy"
)

type Permission struct {
	Action          PermissionAction `json:"action"`
	ResourcePattern string           `json:"resource"`
}

type Resource struct {
	Name string
	Type PermissionArtifactType
}

type User struct {
	Permissions []Permission
}

// Authn

// Principal is the authenticated caller. Identity fields are populated from
// verified token claims by an AuthnProvider; they are empty for the
// PublicSession and SystemSession.
type Principal struct {
	User User

	// Subject is the token's "sub" claim.
	Subject string
	// Issuer is the token's "iss" claim. (Issuer, Subject) identifies the caller.
	Issuer string
	// ClientID is the OAuth client the token was issued to ("azp" or "client_id").
	ClientID string
	// Username is a display name for logs and the UI (for example "preferred_username").
	Username string
	// Roles and Groups are read from the claims configured for the issuer.
	Roles  []string
	Groups []string
	// Actor is the RFC 8693 "act" chain when a client acts on behalf of the
	// subject, outermost actor first. Empty when the subject acts directly.
	Actor []Actor
	// Claims holds every verified claim, for policies that need more than the
	// fields above.
	Claims map[string]any
}

// Actor is one link of an RFC 8693 delegation chain.
type Actor struct {
	Subject string
	Issuer  string
}

// IsAuthenticated reports whether the principal carries a verified identity.
func (p Principal) IsAuthenticated() bool {
	return p.Subject != "" && p.Issuer != ""
}

type Session interface {
	Principal() Principal
}

type AuthnProvider interface {
	Authenticate(ctx context.Context, reqHeaders func(name string) string, query url.Values) (Session, error)
}

// context utils

type sessionKeyType struct{}

var (
	sessionKey = sessionKeyType{}
)

func AuthSessionFrom(ctx context.Context) (Session, bool) {
	v, ok := ctx.Value(sessionKey).(Session)
	return v, ok && v != nil
}

func AuthSessionTo(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, sessionKey, session)
}

// todo: the middleware config is redefined here and router. should be consolidated.
// Middleware configuration options
type middlewareConfig struct {
	skipPaths      map[string]bool // paths that should skip authentication and don't require any authorization (e.g. no need to fetch registry content)
	publicPrefixes []string        // path prefixes for paths that skip authentication, but require access to content (e.g. MCP /v0.1 requires server public listing)
}

type MiddlewareOption func(*middlewareConfig)

// WithSkipPaths marks exact request paths that skip authentication and require
// no authorization. Used for endpoints outside the authz model, such as health
// and metrics. A path must match the whole request path: "/health" does not
// open "/v0/health" or "/v0/agents/health".
func WithSkipPaths(paths ...string) MiddlewareOption {
	return func(c *middlewareConfig) {
		for _, path := range paths {
			c.skipPaths[path] = true
		}
	}
}

// WithPublicPaths marks path prefixes as public: a request without credentials carries a
// PublicSession, so downstream authz hooks can scope what anonymous callers may access,
// while a request with credentials is authenticated like any other.
func WithPublicPaths(prefixes ...string) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.publicPrefixes = append(c.publicPrefixes, prefixes...)
	}
}

func AuthnMiddleware(authn AuthnProvider, options ...MiddlewareOption) func(ctx huma.Context, next func(huma.Context)) {
	config := &middlewareConfig{
		skipPaths: make(map[string]bool),
	}
	for _, option := range options {
		option(config)
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		path := ctx.URL().Path

		// Skip authentication for exact skip paths only.
		if config.skipPaths[path] {
			next(ctx)
			return
		}

		// Public paths admit anonymous callers with a PublicSession. Presented credentials are
		// authenticated instead, so a caller keeps its own permissions and a bad token is refused.
		if ctx.Header("Authorization") == "" {
			for _, prefix := range config.publicPrefixes {
				if strings.HasPrefix(path, prefix) {
					next(huma.WithContext(ctx, WithPublicContext(ctx.Context())))
					return
				}
			}
		}

		url := ctx.URL()
		session, err := authn.Authenticate(ctx.Context(), ctx.Header, url.Query())
		if err != nil {
			slog.Warn("authentication failed", "path", path, "error", err)
			ctx.SetHeader("WWW-Authenticate", "Bearer")
			ctx.SetStatus(http.StatusUnauthorized)
			_, _ = ctx.BodyWriter().Write([]byte("Unauthorized"))
			return
		}
		if session != nil {
			ctx = huma.WithContext(ctx, AuthSessionTo(ctx.Context(), session))
		}
		next(ctx)
	}
}
