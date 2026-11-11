package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/cors"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
)

// Middleware is the stack the API server wraps its mux in. Order: security
// headers and body limit, then TrailingSlash, then CORS.
func Middleware(cfg *config.Config, mux http.Handler) http.Handler {
	return Harden(cfg, TrailingSlashMiddleware(withCORS(cfg, mux)))
}

// Harden wraps h with the protections every registry HTTP server applies:
// security headers on every response and the request body limit.
func Harden(cfg *config.Config, h http.Handler) http.Handler {
	return securityHeaders(cfg, limitBody(cfg.HTTPMaxBodyBytes, h))
}

// securityHeaders sets headers that stop browsers from sniffing content
// types, framing the registry and leaking URLs in referrers, and with
// HTTPHSTSMaxAge set, from using plain HTTP.
func securityHeaders(cfg *config.Config, next http.Handler) http.Handler {
	hsts := ""
	if secs := int64(cfg.HTTPHSTSMaxAge.Seconds()); secs > 0 {
		hsts = fmt.Sprintf("max-age=%d; includeSubDomains", secs)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if hsts != "" {
			h.Set("Strict-Transport-Security", hsts)
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody refuses request bodies over max bytes with 413. Zero means no
// limit.
func limitBody(max int64, next http.Handler) http.Handler {
	if max <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > max {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}

// corsAllowedOrigins returns the origins allowed to call the API across
// sites, or nil for same-origin only. When none are configured, any origin
// is allowed without authentication (the OSS behavior) and none with it.
func corsAllowedOrigins(cfg *config.Config) []string {
	if len(cfg.CORSAllowedOrigins) > 0 {
		return cfg.CORSAllowedOrigins
	}
	if cfg.AuthMode == config.AuthModeRequired {
		return nil
	}
	return []string{"*"}
}

// withCORS answers cross-origin requests from the allowed origins. With
// none allowed it adds nothing, so browsers keep the same-origin policy.
func withCORS(cfg *config.Config, next http.Handler) http.Handler {
	origins := corsAllowedOrigins(cfg)
	if len(origins) == 0 {
		return next
	}
	return cors.New(cors.Options{
		AllowedOrigins: origins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{"*"},
		ExposedHeaders: []string{"Content-Type", "Content-Length", "WWW-Authenticate", "X-Request-ID"},
		// Callers authenticate with bearer tokens, never cookies.
		AllowCredentials: false,
		MaxAge:           86400, // 24 hours
	}).Handler(next)
}

// uiContentSecurityPolicy is the policy sent with the web UI: its own files,
// plus the sign-in service, which the browser calls to exchange and renew
// tokens. Next.js inlines its bootstrap scripts and styles, so inline code
// is allowed; nothing else is, and the UI cannot be framed.
func uiContentSecurityPolicy(cfg *config.Config) string {
	if cfg.HTTPCSP != "" {
		return cfg.HTTPCSP
	}
	idp := ""
	if u, err := url.Parse(cfg.AuthUIIssuer); err == nil && u.Scheme != "" && u.Host != "" {
		idp = " " + u.Scheme + "://" + u.Host
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self' data:",
		"connect-src 'self'" + idp,
		"frame-src 'self'" + idp,
		"form-action 'self'" + idp,
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"object-src 'none'",
	}, "; ")
}

// withUIContentSecurityPolicy sends policy with every web UI response.
func withUIContentSecurityPolicy(policy string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		next.ServeHTTP(w, r)
	})
}
