package config

import (
	"log/slog"
	"os"
	"strconv"
	"time"

	env "github.com/caarlos0/env/v11"
)

// Config holds the application configuration
// See .env.example for more documentation
type Config struct {
	ServerAddress            string `env:"SERVER_ADDRESS" envDefault:":8080"`
	MCPPort                  uint16 `env:"MCP_PORT" envDefault:"0"`
	DatabaseURL              string `env:"DATABASE_URL" envDefault:"postgres://agentregistry:agentregistry@localhost:5432/agentregistry?sslmode=disable"`
	Version                  string `env:"VERSION" envDefault:"dev"`
	LogLevel                 string `env:"LOG_LEVEL" envDefault:"info"`
	SecretStore              string `env:"SECRET_STORE" envDefault:""`
	SecretStoreEncryptionKey string `env:"SECRET_STORE_ENCRYPTION_KEY" envDefault:""`
	SecretStoreNamespace     string `env:"SECRET_STORE_KUBERNETES_NAMESPACE" envDefault:"agentregistry-system"`

	// MCP Registry compatibility (read-only)
	//
	// MCPRegistryCompatEnabled toggles the read-only MCP Registry v0.1
	// compatibility API (GET /v0.1/servers ...), which re-exposes MCPServer
	// resources in the official server.json shape so registry-aware clients
	// (e.g. VS Code's MCP gallery) can discover them. The endpoint is
	// anonymous and flattens every namespace into one catalogue, and it
	// bypasses per-kind RBAC list filters, so it is OFF by default — enable
	// it only where an unauthenticated, cross-namespace MCP catalogue is
	// acceptable (a public OSS registry, or behind a trusted gateway).
	MCPRegistryCompatEnabled bool `env:"MCP_REGISTRY_COMPAT_ENABLED" envDefault:"false"`
	// MCPRegistryCompatPathPrefix optionally mounts the compatibility API
	// under a base prefix (e.g. "/mcp-registry"); empty serves the spec's
	// standard paths at the root. Clients append "/v0.1/servers" to the base
	// URL they're configured with, so any prefix set here must match that
	// configured base.
	MCPRegistryCompatPathPrefix string `env:"MCP_REGISTRY_COMPAT_PATH_PREFIX" envDefault:""`

	// Plugin marketplace compatibility (read-only)
	//
	// PluginMarketplaceCompatEnabled toggles the read-only Claude Code
	// marketplace.json compatibility API (GET /plugin-marketplace/marketplace.json),
	// which re-exposes resolved Plugin resources in the marketplace.json shape
	// so a bare URL to this endpoint can be registered directly with
	// `claude plugin marketplace add`. The endpoint flattens every namespace
	// into one catalogue and honors the same per-kind RBAC list filter as the
	// native Plugin read path (nil = public OSS behavior), so it is OFF by
	// default — enable it only where a Plugin catalogue at this scope is
	// acceptable (a public OSS registry, or behind a trusted gateway).
	PluginMarketplaceCompatEnabled bool `env:"PLUGIN_MARKETPLACE_COMPAT_ENABLED" envDefault:"false"`
	// PluginMarketplaceCompatPathPrefix optionally mounts the compatibility API
	// under a base prefix (e.g. "/plugins"); empty serves the standard
	// "/plugin-marketplace/marketplace.json" path at the root. Any prefix set
	// here must match the base URL registered with the consuming agent.
	PluginMarketplaceCompatPathPrefix string `env:"PLUGIN_MARKETPLACE_COMPAT_PATH_PREFIX" envDefault:""`

	// ControllerEventRetention is how long handled control-plane events remain
	// available for checkpoint replay. Set to 0 to disable event pruning.
	ControllerEventRetention time.Duration `env:"CONTROLLER_EVENT_RETENTION" envDefault:"24h"`
	// ControllerEventKeepAfterRevision preserves control-plane events newer than
	// this Postgres revision even when they are older than ControllerEventRetention.
	ControllerEventKeepAfterRevision int64 `env:"CONTROLLER_EVENT_KEEP_AFTER_REVISION" envDefault:"0"`
	// ControllerRetentionPruneBatchLimit caps rows removed per retention pass so
	// pruning cannot monopolize the database during startup or repair loops.
	ControllerRetentionPruneBatchLimit int `env:"CONTROLLER_RETENTION_PRUNE_BATCH_LIMIT" envDefault:"500"`
	// ControllerDiscoveryInterval is how often provider discovery snapshots are
	// materialized into discovered Deployment rows. Provider-specific cache
	// refreshes may have separate intervals.
	ControllerDiscoveryInterval time.Duration `env:"CONTROLLER_DISCOVERY_INTERVAL" envDefault:"60s"`
	// ControllerDiscoveryStaleAfterMisses is how many consecutive successful
	// discovery polls may omit a discovered Deployment before it is marked
	// not-ready/stale.
	ControllerDiscoveryStaleAfterMisses int `env:"CONTROLLER_DISCOVERY_STALE_AFTER_MISSES" envDefault:"3"`
	// ControllerDiscoveryDeleteAfterMisses is how many consecutive successful
	// discovery polls may omit a discovered Deployment before it is deleted.
	ControllerDiscoveryDeleteAfterMisses int `env:"CONTROLLER_DISCOVERY_DELETE_AFTER_MISSES" envDefault:"5"`

	// Authentication
	//
	// AuthMode is "disabled" (default; no authentication, the OSS behavior) or
	// "required". With "required" the server refuses to start unless an
	// AuthZEN PDP and at least one issuer (or an AuthnProvider in AppOptions)
	// are configured, and every request except AuthOpenPaths must carry a
	// valid token.
	AuthMode string `env:"AUTH_MODE" envDefault:"disabled"`
	// AuthIssuers is a JSON array of trusted token issuers (see
	// pkg/registry/auth/jwt.IssuerConfig). AuthIssuersFile reads the same
	// JSON from a file and wins when both are set.
	AuthIssuers     string `env:"AUTH_ISSUERS" envDefault:""`
	AuthIssuersFile string `env:"AUTH_ISSUERS_FILE" envDefault:""`
	// AuthClockSkew is the leeway applied to exp, nbf and iat.
	AuthClockSkew time.Duration `env:"AUTH_CLOCK_SKEW" envDefault:"30s"`
	// AuthOpenPaths are exact paths served without authentication.
	AuthOpenPaths []string `env:"AUTH_OPEN_PATHS" envSeparator:"," envDefault:"/health,/ping,/version"`
	// The web UI signs users in with the OAuth 2.0 authorization code flow
	// and PKCE against AuthUIIssuer, as the public client AuthUIClientID. It
	// reads these from /auth-config.json at runtime. Both are required for
	// the UI to sign in when AuthMode is "required".
	AuthUIIssuer   string `env:"AUTH_UI_ISSUER" envDefault:""`
	AuthUIClientID string `env:"AUTH_UI_CLIENT_ID" envDefault:""`
	AuthUIScopes   string `env:"AUTH_UI_SCOPES" envDefault:"openid profile email"`
	// AuthMCPResource is the public URL of the MCP endpoint (for example
	// https://registry.example.com/mcp). When set with auth required, the MCP
	// server publishes RFC 9728 protected-resource metadata naming the
	// configured issuers, and its 401 challenges point to it, so MCP clients
	// can discover where to get a token.
	AuthMCPResource string `env:"AUTH_MCP_RESOURCE" envDefault:""`
	// AuthMCPScopes are advertised as scopes_supported in that metadata.
	AuthMCPScopes []string `env:"AUTH_MCP_SCOPES" envSeparator:"," envDefault:""`

	// Authorization (OpenID AuthZEN 1.0 PDP)
	//
	// AuthzenURL is the PDP base URL; endpoints are discovered from
	// <AuthzenURL>/.well-known/authzen-configuration.
	AuthzenURL string `env:"AUTHZEN_URL" envDefault:""`
	// AuthzenTimeout bounds every PDP call; a timeout is a denial.
	AuthzenTimeout time.Duration `env:"AUTHZEN_TIMEOUT" envDefault:"1500ms"`
	// AuthzenCacheTTL caches permit decisions per (subject, action, resource).
	// 0 disables caching. Denials are never cached.
	AuthzenCacheTTL time.Duration `env:"AUTHZEN_CACHE_TTL" envDefault:"5s"`
	// The registry authenticates to the PDP with an OAuth 2.0
	// client-credentials token when AuthzenTokenURL is set...
	AuthzenTokenURL         string   `env:"AUTHZEN_TOKEN_URL" envDefault:""`
	AuthzenClientID         string   `env:"AUTHZEN_CLIENT_ID" envDefault:""`
	AuthzenClientSecret     string   `env:"AUTHZEN_CLIENT_SECRET" envDefault:""`
	AuthzenClientSecretFile string   `env:"AUTHZEN_CLIENT_SECRET_FILE" envDefault:""`
	AuthzenScopes           []string `env:"AUTHZEN_SCOPES" envSeparator:"," envDefault:""`
	// ...or, as a fallback for PDPs without OAuth, with a static bearer token.
	AuthzenStaticToken     string `env:"AUTHZEN_STATIC_TOKEN" envDefault:""`
	AuthzenStaticTokenFile string `env:"AUTHZEN_STATIC_TOKEN_FILE" envDefault:""`
	// AuthzenListMax caps how many rows a list filter authorizes per request.
	AuthzenListMax int `env:"AUTHZEN_LIST_MAX" envDefault:"1000"`

	// SkipMigrations gates the server's Postgres migrator at startup.
	// Set true when migrations are applied out-of-band (e.g. by
	// `arctl db migrate up` from CI/CD ahead of the rollout).
	// Populated from the unprefixed SKIP_MIGRATIONS env var (see
	// NewConfig) — deliberately prefix-free so the same name toggles
	// the gate across binaries regardless of their env prefix.
	// AppOptions.SkipMigrations wins over this env value when set
	// programmatically.
	SkipMigrations bool `env:"-"`
}

// NewConfig creates a new configuration with default values.
//
// Server-only entry point: NewConfig is called from registry.App() at
// server start; arctl does not call NewConfig, so the os.Exit(1)
// branches below (caarlos0/env parse failure and the SKIP_MIGRATIONS
// parse) cannot fire during CLI invocations like `arctl db
// migrate`.
func NewConfig() *Config {
	var cfg Config
	err := env.ParseWithOptions(&cfg, env.Options{
		Prefix: "AGENT_REGISTRY_",
	})
	if err != nil {
		slog.Error("failed to parse config", "error", err)
		os.Exit(1)
	}

	// SkipMigrations reads the unprefixed SKIP_MIGRATIONS rather than the
	// AGENT_REGISTRY_ prefix the other fields use, so the same env var
	// toggles the gate across binaries regardless of their prefix. An
	// invalid value fails NewConfig loudly (mirroring caarlos0/env above)
	// rather than silently falling back to false.
	if raw, ok := os.LookupEnv("SKIP_MIGRATIONS"); ok {
		parsed, perr := strconv.ParseBool(raw)
		if perr != nil {
			slog.Error("failed to parse SKIP_MIGRATIONS", "value", raw, "error", perr)
			os.Exit(1)
		}
		cfg.SkipMigrations = parsed
	}

	return &cfg
}
