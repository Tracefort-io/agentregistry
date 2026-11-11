package config

import (
	"fmt"
	"net/url"
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
	return validateAuth(cfg)
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
	if cfg.AuthUIIssuer != "" {
		if u, err := url.Parse(cfg.AuthUIIssuer); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("AUTH_UI_ISSUER must be an absolute http(s) URL")
		}
	}
	if cfg.AuthClockSkew < 0 {
		return fmt.Errorf("auth clock skew must be non-negative")
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
