package config

import (
	"fmt"
	"net/url"
	"time"
)

// Validate performs runtime validations on the loaded configuration.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if cfg.ControllerEventRetention < 0 {
		return fmt.Errorf("controller event retention must be non-negative")
	}
	if cfg.ControllerEventKeepAfterRevision < 0 {
		return fmt.Errorf("controller event keep-after revision must be non-negative")
	}
	if cfg.ControllerRetentionPruneBatchLimit < 0 {
		return fmt.Errorf("controller retention prune batch limit must be non-negative")
	}
	if err := validateHTTP(cfg); err != nil {
		return err
	}
	if cfg.AuditRetention < 0 {
		return fmt.Errorf("audit retention must be non-negative")
	}
	if err := validateLeaderElection(cfg); err != nil {
		return err
	}
	if err := validateOpenBao(cfg); err != nil {
		return err
	}
	if err := validateApprovals(cfg); err != nil {
		return err
	}
	return validateAuth(cfg)
}

// validateHTTP checks the HTTP hardening settings. Zero timeouts and a zero
// body limit mean none, as in net/http.
func validateHTTP(cfg *Config) error {
	if cfg.HTTPReadTimeout < 0 || cfg.HTTPWriteTimeout < 0 || cfg.HTTPIdleTimeout < 0 {
		return fmt.Errorf("HTTP timeouts must be non-negative")
	}
	if cfg.HTTPMaxBodyBytes < 0 {
		return fmt.Errorf("HTTP max body bytes must be non-negative")
	}
	if cfg.HTTPHSTSMaxAge < 0 {
		return fmt.Errorf("HTTP HSTS max age must be non-negative")
	}
	for _, origin := range cfg.CORSAllowedOrigins {
		if origin == "*" {
			if len(cfg.CORSAllowedOrigins) > 1 {
				return fmt.Errorf("CORS_ALLOWED_ORIGINS: \"*\" cannot be combined with other origins")
			}
			continue
		}
		if !isOrigin(origin) {
			return fmt.Errorf("CORS_ALLOWED_ORIGINS: %q is not an origin (scheme://host[:port])", origin)
		}
	}
	return nil
}

// isOrigin reports whether s is a browser origin: an http(s) scheme and a
// host, with nothing after them.
func isOrigin(s string) bool {
	u, err := url.Parse(s)
	return err == nil && isHTTPURL(s) && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// Auth modes accepted in AuthMode.
const (
	AuthModeDisabled = "disabled"
	AuthModeRequired = "required"
)

// validateAuth fails closed: with AuthMode "required" the server must not
// start unless it can both authenticate callers and reach an AuthZEN PDP.
func validateAuth(cfg *Config) error {
	switch cfg.AuthMode {
	case "", AuthModeDisabled:
		return nil
	case AuthModeRequired:
	default:
		return fmt.Errorf("auth mode must be %q or %q, got %q", AuthModeDisabled, AuthModeRequired, cfg.AuthMode)
	}
	// Issuers are checked at startup instead, where an AuthnProvider supplied
	// in AppOptions can stand in for them.
	if cfg.AuthzenURL == "" {
		return fmt.Errorf("auth mode %q requires AUTHZEN_URL", AuthModeRequired)
	}
	if (cfg.AuthUIIssuer == "") != (cfg.AuthUIClientID == "") {
		return fmt.Errorf("set both AUTH_UI_ISSUER and AUTH_UI_CLIENT_ID, or neither")
	}
	if cfg.AuthUIIssuer != "" && !isHTTPURL(cfg.AuthUIIssuer) {
		return fmt.Errorf("AUTH_UI_ISSUER must be an absolute http(s) URL")
	}
	if cfg.AuthMCPResource != "" {
		if !isHTTPURL(cfg.AuthMCPResource) {
			return fmt.Errorf("AUTH_MCP_RESOURCE must be an absolute http(s) URL")
		}
		if u, _ := url.Parse(cfg.AuthMCPResource); u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("AUTH_MCP_RESOURCE must not have a query or fragment")
		}
	}
	if cfg.AuthClockSkew < 0 {
		return fmt.Errorf("auth clock skew must be non-negative")
	}
	if cfg.AuthJWKSRefresh < time.Second {
		return fmt.Errorf("auth JWKS refresh must be at least 1s")
	}
	if cfg.AuthzenTimeout <= 0 {
		return fmt.Errorf("authzen timeout must be positive")
	}
	if cfg.AuthzenCacheTTL < 0 {
		return fmt.Errorf("authzen cache TTL must be non-negative")
	}
	if cfg.AuthzenListMax <= 0 {
		return fmt.Errorf("authzen list max must be positive")
	}
	hasOAuth := cfg.AuthzenTokenURL != ""
	hasStatic := cfg.AuthzenStaticToken != "" || cfg.AuthzenStaticTokenFile != ""
	if hasOAuth && hasStatic {
		return fmt.Errorf("set either AUTHZEN_TOKEN_URL or AUTHZEN_STATIC_TOKEN(_FILE), not both")
	}
	if hasOAuth && (cfg.AuthzenClientID == "" || (cfg.AuthzenClientSecret == "" && cfg.AuthzenClientSecretFile == "")) {
		return fmt.Errorf("AUTHZEN_TOKEN_URL requires AUTHZEN_CLIENT_ID and AUTHZEN_CLIENT_SECRET(_FILE)")
	}
	return nil
}

// isHTTPURL reports whether s is an absolute http(s) URL with a host.
func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// Leader election mechanisms accepted in LeaderElection.
const (
	LeaderElectionPostgres   = "postgres"
	LeaderElectionKubernetes = "kubernetes"
	LeaderElectionNone       = "none"
)

// validateLeaderElection checks the mechanism and that the leader gives up
// before anyone can take over: retry period < renew deadline < lease
// duration. An empty mechanism (a Config built in code) means none.
func validateLeaderElection(cfg *Config) error {
	switch cfg.LeaderElection {
	case "", LeaderElectionNone:
		return nil
	case LeaderElectionPostgres, LeaderElectionKubernetes:
	default:
		return fmt.Errorf("LEADER_ELECTION must be %q, %q or %q, got %q",
			LeaderElectionPostgres, LeaderElectionKubernetes, LeaderElectionNone, cfg.LeaderElection)
	}
	if cfg.LeaderElectionName == "" {
		return fmt.Errorf("LEADER_ELECTION_NAME must not be empty")
	}
	if cfg.LeaderElectionRetryPeriod <= 0 ||
		cfg.LeaderElectionRenewDeadline <= cfg.LeaderElectionRetryPeriod ||
		cfg.LeaderElectionLeaseDuration <= cfg.LeaderElectionRenewDeadline {
		return fmt.Errorf("leader election timing must satisfy 0 < retry period < renew deadline < lease duration")
	}
	return nil
}

// validateOpenBao checks the OpenBao secret store settings, and the
// migration source, when SECRET_STORE is OpenBao.
func validateOpenBao(cfg *Config) error {
	if cfg.SecretStoreMigrateFrom != "" {
		if cfg.SecretStore == "" || cfg.SecretStoreMigrateFrom == cfg.SecretStore {
			return fmt.Errorf("SECRET_STORE_MIGRATE_FROM must name a store other than SECRET_STORE")
		}
		if cfg.SecretStoreMigrateFrom != "Kubernetes" && cfg.SecretStoreMigrateFrom != "Database" {
			return fmt.Errorf("SECRET_STORE_MIGRATE_FROM must be Kubernetes or Database, got %q", cfg.SecretStoreMigrateFrom)
		}
	}
	if cfg.SecretStore != "OpenBao" {
		return nil
	}
	if !isHTTPURL(cfg.OpenBaoAddr) {
		return fmt.Errorf("SECRET_STORE=OpenBao needs OPENBAO_ADDR, an http(s) URL")
	}
	if cfg.OpenBaoMount == "" {
		return fmt.Errorf("OPENBAO_MOUNT must not be empty")
	}
	if cfg.OpenBaoTimeout <= 0 {
		return fmt.Errorf("OPENBAO_TIMEOUT must be positive")
	}
	switch cfg.OpenBaoAuth {
	case "kubernetes":
		if cfg.OpenBaoRole == "" {
			return fmt.Errorf("OPENBAO_AUTH=kubernetes needs OPENBAO_ROLE")
		}
	case "approle":
		if cfg.OpenBaoAppRoleRoleIDFile == "" || cfg.OpenBaoAppRoleSecretIDFile == "" {
			return fmt.Errorf("OPENBAO_AUTH=approle needs OPENBAO_APPROLE_ROLE_ID_FILE and OPENBAO_APPROLE_SECRET_ID_FILE")
		}
	case "token":
		if cfg.OpenBaoTokenFile == "" {
			return fmt.Errorf("OPENBAO_AUTH=token needs OPENBAO_TOKEN_FILE")
		}
	default:
		return fmt.Errorf("OPENBAO_AUTH must be kubernetes, approle or token, got %q", cfg.OpenBaoAuth)
	}
	return nil
}

// validateApprovals checks the approvals settings when they are on.
func validateApprovals(cfg *Config) error {
	if !cfg.ApprovalsEnabled {
		return nil
	}
	if cfg.AuthMode != AuthModeRequired {
		return fmt.Errorf("APPROVALS_ENABLED needs AUTH_MODE=required: approvals are decided by the AuthZEN PDP")
	}
	if !isHTTPURL(cfg.ApprovalsTokenURL) || cfg.ApprovalsClientID == "" ||
		(cfg.ApprovalsClientSecret == "" && cfg.ApprovalsClientSecretFile == "") {
		return fmt.Errorf("APPROVALS_ENABLED needs APPROVALS_TOKEN_URL, APPROVALS_CLIENT_ID and APPROVALS_CLIENT_SECRET(_FILE): the registry's credentials for the access request service")
	}
	if cfg.ApprovalsPollInterval < time.Second {
		return fmt.Errorf("APPROVALS_POLL_INTERVAL must be at least 1s")
	}
	if cfg.ApprovalsCallbackURL != "" {
		u, err := url.Parse(cfg.ApprovalsCallbackURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("APPROVALS_CALLBACK_URL must be an https URL: the access request service only calls https")
		}
		if cfg.ApprovalsCallbackSecretFile == "" {
			return fmt.Errorf("APPROVALS_CALLBACK_URL needs APPROVALS_CALLBACK_SECRET_FILE")
		}
	}
	return nil
}
