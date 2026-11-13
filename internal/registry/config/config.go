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
	// SecretStoreMigrateFrom ("Kubernetes" or "Database") copies, at
	// startup, every Secret payload missing from the configured store from
	// that earlier store. Originals are left in place.
	SecretStoreMigrateFrom string `env:"SECRET_STORE_MIGRATE_FROM" envDefault:""`

	// OpenBao secret store (SECRET_STORE=OpenBao): payloads live in a KV v2
	// engine at <OpenBaoMount>/data/<OpenBaoPathPrefix>/<namespace>/<name>.
	OpenBaoAddr       string `env:"OPENBAO_ADDR" envDefault:""`
	OpenBaoNamespace  string `env:"OPENBAO_NAMESPACE" envDefault:""`
	OpenBaoMount      string `env:"OPENBAO_MOUNT" envDefault:"agentregistry"`
	OpenBaoPathPrefix string `env:"OPENBAO_PATH_PREFIX" envDefault:"secrets"`
	// OpenBaoAuth is "kubernetes" (the pod's service account), "approle" or
	// "token" (a token file, for development).
	OpenBaoAuth string `env:"OPENBAO_AUTH" envDefault:"kubernetes"`
	// OpenBaoAuthMount is the auth method's path; empty means its default
	// ("kubernetes" or "approle").
	OpenBaoAuthMount           string        `env:"OPENBAO_AUTH_MOUNT" envDefault:""`
	OpenBaoRole                string        `env:"OPENBAO_ROLE" envDefault:"agentregistry"`
	OpenBaoKubernetesTokenFile string        `env:"OPENBAO_KUBERNETES_TOKEN_FILE" envDefault:""`
	OpenBaoAppRoleRoleIDFile   string        `env:"OPENBAO_APPROLE_ROLE_ID_FILE" envDefault:""`
	OpenBaoAppRoleSecretIDFile string        `env:"OPENBAO_APPROLE_SECRET_ID_FILE" envDefault:""`
	OpenBaoTokenFile           string        `env:"OPENBAO_TOKEN_FILE" envDefault:""`
	OpenBaoCACertFile          string        `env:"OPENBAO_CA_CERT_FILE" envDefault:""`
	OpenBaoTimeout             time.Duration `env:"OPENBAO_TIMEOUT" envDefault:"10s"`

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
	// AuthJWKSRefresh is how often each issuer's signing keys are fetched
	// again, and so how long a key the IdP has removed (for example after a
	// leak) is still trusted. New keys are picked up at once regardless.
	AuthJWKSRefresh time.Duration `env:"AUTH_JWKS_REFRESH" envDefault:"5m"`
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

	// HTTP hardening
	//
	// CORSAllowedOrigins are the browser origins (scheme://host[:port]) that
	// may call the API from another site, or "*" for any. Empty means "*"
	// with AuthMode "disabled" (the OSS behavior) and same-origin only with
	// AuthMode "required".
	CORSAllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:"," envDefault:""`
	// Timeouts of the HTTP servers. The MCP server streams responses, so it
	// applies the read and idle timeouts but not the write timeout.
	HTTPReadTimeout  time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"30s"`
	HTTPWriteTimeout time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"2m"`
	HTTPIdleTimeout  time.Duration `env:"HTTP_IDLE_TIMEOUT" envDefault:"2m"`
	// HTTPMaxBodyBytes caps every request body; larger requests get 413. API
	// operations also apply their own limit (1 MiB unless an operation says
	// otherwise), so raising this alone does not raise theirs.
	HTTPMaxBodyBytes int64 `env:"HTTP_MAX_BODY_BYTES" envDefault:"1048576"`
	// HTTPHSTSMaxAge, when above zero, sends Strict-Transport-Security so
	// browsers use only HTTPS. Set it when the registry (or the gateway in
	// front) is served over HTTPS.
	HTTPHSTSMaxAge time.Duration `env:"HTTP_HSTS_MAX_AGE" envDefault:"0s"`
	// HTTPCSP replaces the Content-Security-Policy sent with the web UI. By
	// default it allows the registry's own origin and AuthUIIssuer's.
	HTTPCSP string `env:"HTTP_CSP" envDefault:""`

	// Leader election
	//
	// LeaderElection chooses how replicas elect the one that runs the
	// background controllers (Deployment reconciliation and discovery,
	// Plugin and Skill pinning); every replica serves the API.
	//   postgres    a session advisory lock in the registry's database
	//   kubernetes  a coordination.k8s.io Lease (needs RBAC on leases)
	//   none        every replica runs the controllers: one replica only
	// All replicas must use the same setting.
	LeaderElection string `env:"LEADER_ELECTION" envDefault:"postgres"`
	// LeaderElectionName names the lock or Lease replicas compete for.
	LeaderElectionName string `env:"LEADER_ELECTION_NAME" envDefault:"agentregistry-controllers"`
	// LeaderElectionNamespace holds the Lease; empty means the pod's own
	// namespace.
	LeaderElectionNamespace string `env:"LEADER_ELECTION_NAMESPACE" envDefault:""`
	// LeaderElectionIdentity names this replica in the Lease; empty means
	// the host (pod) name.
	LeaderElectionIdentity string `env:"LEADER_ELECTION_IDENTITY" envDefault:""`
	// Timing: others take over a silent leader after the lease duration; the
	// leader stops if it cannot renew (or confirm its Postgres connection)
	// within the renew deadline; everyone retries every retry period. A new
	// Postgres leader also waits the renew deadline before it starts.
	LeaderElectionLeaseDuration time.Duration `env:"LEADER_ELECTION_LEASE_DURATION" envDefault:"15s"`
	LeaderElectionRenewDeadline time.Duration `env:"LEADER_ELECTION_RENEW_DEADLINE" envDefault:"10s"`
	LeaderElectionRetryPeriod   time.Duration `env:"LEADER_ELECTION_RETRY_PERIOD" envDefault:"2s"`

	// Audit log
	//
	// AuditEnabled records every apply and delete, and every read the
	// authorization service refused, in the audit_events table, served to
	// registry admins at GET /v0/audit.
	AuditEnabled bool `env:"AUDIT_ENABLED" envDefault:"true"`
	// AuditRetention is how long events are kept; 0 keeps them forever.
	AuditRetention time.Duration `env:"AUDIT_RETENTION" envDefault:"2160h"`
	// AuditOTLP also exports each event as an OpenTelemetry log record over
	// OTLP/HTTP, configured by the standard OTEL_EXPORTER_OTLP_* variables
	// (for example OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318).
	AuditOTLP bool `env:"AUDIT_OTLP" envDefault:"false"`

	// Approvals (OpenID AuthZEN Access Request and Approval Profile)
	//
	// ApprovalsEnabled holds batch-apply writes that the PDP refuses but
	// marks requestable, submits them to the PDP's access request service,
	// and applies them once approved. Which changes need approval and who
	// approves them is the PDP policy's decision. Needs AUTH_MODE=required.
	ApprovalsEnabled bool `env:"APPROVALS_ENABLED" envDefault:"false"`
	// The registry's own OAuth client, accepted by the access request
	// service's caller_auth: it submits requests and reads their status.
	ApprovalsTokenURL         string   `env:"APPROVALS_TOKEN_URL" envDefault:""`
	ApprovalsClientID         string   `env:"APPROVALS_CLIENT_ID" envDefault:""`
	ApprovalsClientSecret     string   `env:"APPROVALS_CLIENT_SECRET" envDefault:""`
	ApprovalsClientSecretFile string   `env:"APPROVALS_CLIENT_SECRET_FILE" envDefault:""`
	ApprovalsScopes           []string `env:"APPROVALS_SCOPES" envSeparator:"," envDefault:""`
	// ApprovalsPollInterval is how often the leader checks held requests.
	ApprovalsPollInterval time.Duration `env:"APPROVALS_POLL_INTERVAL" envDefault:"15s"`
	// ApprovalsCallbackURL, when set, is the https URL of this registry's
	// POST /approvals/callback, which the service calls when a request
	// ends; ApprovalsCallbackSecretFile holds the shared HMAC secret.
	ApprovalsCallbackURL        string `env:"APPROVALS_CALLBACK_URL" envDefault:""`
	ApprovalsCallbackSecretFile string `env:"APPROVALS_CALLBACK_SECRET_FILE" envDefault:""`

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
