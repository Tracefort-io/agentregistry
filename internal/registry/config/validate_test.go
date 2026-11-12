package config

import (
	"slices"
	"testing"
	"time"
)

func TestNewConfig_AuthDefaults(t *testing.T) {
	cfg := NewConfig()

	if cfg.AuthMode != AuthModeDisabled {
		t.Fatalf("AuthMode = %q, want %q", cfg.AuthMode, AuthModeDisabled)
	}
	if want := []string{"/health", "/ping", "/version"}; !slices.Equal(cfg.AuthOpenPaths, want) {
		t.Fatalf("AuthOpenPaths = %v, want %v", cfg.AuthOpenPaths, want)
	}
	if cfg.AuthzenTimeout != 1500*time.Millisecond {
		t.Fatalf("AuthzenTimeout = %s, want 1.5s", cfg.AuthzenTimeout)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate(defaults) = %v, want nil", err)
	}
}

func TestNewConfig_AuthEnv(t *testing.T) {
	t.Setenv("AGENT_REGISTRY_AUTH_MODE", "required")
	t.Setenv("AGENT_REGISTRY_AUTH_OPEN_PATHS", "/health,/ping")
	t.Setenv("AGENT_REGISTRY_AUTHZEN_SCOPES", "pdp.read,pdp.eval")

	cfg := NewConfig()

	if cfg.AuthMode != AuthModeRequired {
		t.Fatalf("AuthMode = %q, want %q", cfg.AuthMode, AuthModeRequired)
	}
	if want := []string{"/health", "/ping"}; !slices.Equal(cfg.AuthOpenPaths, want) {
		t.Fatalf("AuthOpenPaths = %v, want %v", cfg.AuthOpenPaths, want)
	}
	if want := []string{"pdp.read", "pdp.eval"}; !slices.Equal(cfg.AuthzenScopes, want) {
		t.Fatalf("AuthzenScopes = %v, want %v", cfg.AuthzenScopes, want)
	}
}

func TestValidate_Auth(t *testing.T) {
	// required returns a config that passes validation with auth required.
	required := func(mutate func(*Config)) *Config {
		cfg := &Config{
			AuthMode:        AuthModeRequired,
			AuthIssuers:     `[{"issuer":"https://idp.example.com","audiences":["agentregistry"]}]`,
			AuthClockSkew:   30 * time.Second,
			AuthJWKSRefresh: 5 * time.Minute,
			AuthzenURL:      "https://pdp.example.com",
			AuthzenTimeout:  time.Second,
			AuthzenListMax:  1000,
		}
		if mutate != nil {
			mutate(cfg)
		}
		return cfg
	}

	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"disabled needs nothing", &Config{AuthMode: AuthModeDisabled}, false},
		{"empty mode means disabled", &Config{}, false},
		{"unknown mode", &Config{AuthMode: "optional"}, true},
		{"required and complete", required(nil), false},
		{"issuers from file", required(func(c *Config) { c.AuthIssuers, c.AuthIssuersFile = "", "/etc/issuers.json" }), false},
		// Issuers are checked at startup, where a provider from AppOptions can stand in for them.
		{"required without issuers", required(func(c *Config) { c.AuthIssuers = "" }), false},
		{"required without pdp", required(func(c *Config) { c.AuthzenURL = "" }), true},
		{"negative clock skew", required(func(c *Config) { c.AuthClockSkew = -time.Second }), true},
		{"jwks refresh under 1s", required(func(c *Config) { c.AuthJWKSRefresh = 500 * time.Millisecond }), true},
		{"zero pdp timeout", required(func(c *Config) { c.AuthzenTimeout = 0 }), true},
		{"negative cache ttl", required(func(c *Config) { c.AuthzenCacheTTL = -time.Second }), true},
		{"zero list max", required(func(c *Config) { c.AuthzenListMax = 0 }), true},
		{"oauth complete", required(func(c *Config) {
			c.AuthzenTokenURL, c.AuthzenClientID, c.AuthzenClientSecret = "https://idp.example.com/token", "agentregistry", "s3cret"
		}), false},
		{"oauth secret from file", required(func(c *Config) {
			c.AuthzenTokenURL, c.AuthzenClientID, c.AuthzenClientSecretFile = "https://idp.example.com/token", "agentregistry", "/run/secret"
		}), false},
		{"oauth without client id", required(func(c *Config) {
			c.AuthzenTokenURL, c.AuthzenClientSecret = "https://idp.example.com/token", "s3cret"
		}), true},
		{"oauth without secret", required(func(c *Config) {
			c.AuthzenTokenURL, c.AuthzenClientID = "https://idp.example.com/token", "agentregistry"
		}), true},
		{"oauth and static token together", required(func(c *Config) {
			c.AuthzenTokenURL, c.AuthzenClientID, c.AuthzenClientSecret = "https://idp.example.com/token", "agentregistry", "s3cret"
			c.AuthzenStaticToken = "tok"
		}), true},
		{"static token only", required(func(c *Config) { c.AuthzenStaticTokenFile = "/run/pdp-token" }), false},
		{"ui sign-in configured", required(func(c *Config) {
			c.AuthUIIssuer, c.AuthUIClientID = "https://idp.example.com/realms/r", "agentregistry-ui"
		}), false},
		{"ui issuer without client", required(func(c *Config) { c.AuthUIIssuer = "https://idp.example.com/realms/r" }), true},
		{"ui client without issuer", required(func(c *Config) { c.AuthUIClientID = "agentregistry-ui" }), true},
		{"ui issuer not a url", required(func(c *Config) { c.AuthUIIssuer, c.AuthUIClientID = "idp", "agentregistry-ui" }), true},
		{"mcp resource", required(func(c *Config) { c.AuthMCPResource = "https://registry.example.com/mcp" }), false},
		{"mcp resource not a url", required(func(c *Config) { c.AuthMCPResource = "registry/mcp" }), true},
		{"mcp resource with query", required(func(c *Config) { c.AuthMCPResource = "https://registry.example.com/mcp?x=1" }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_HTTP(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"zero values mean none", &Config{}, false},
		{"defaults", &Config{HTTPReadTimeout: 30 * time.Second, HTTPWriteTimeout: 2 * time.Minute, HTTPIdleTimeout: 2 * time.Minute, HTTPMaxBodyBytes: 1 << 20}, false},
		{"negative read timeout", &Config{HTTPReadTimeout: -time.Second}, true},
		{"negative write timeout", &Config{HTTPWriteTimeout: -time.Second}, true},
		{"negative idle timeout", &Config{HTTPIdleTimeout: -time.Second}, true},
		{"negative body limit", &Config{HTTPMaxBodyBytes: -1}, true},
		{"negative hsts", &Config{HTTPHSTSMaxAge: -time.Second}, true},
		{"any origin", &Config{CORSAllowedOrigins: []string{"*"}}, false},
		{"origins", &Config{CORSAllowedOrigins: []string{"https://portal.example.com", "http://localhost:3000"}}, false},
		{"any origin mixed with others", &Config{CORSAllowedOrigins: []string{"*", "https://portal.example.com"}}, true},
		{"origin with path", &Config{CORSAllowedOrigins: []string{"https://portal.example.com/app"}}, true},
		{"origin with trailing slash", &Config{CORSAllowedOrigins: []string{"https://portal.example.com/"}}, true},
		{"origin without scheme", &Config{CORSAllowedOrigins: []string{"portal.example.com"}}, true},
		{"origin with other scheme", &Config{CORSAllowedOrigins: []string{"ftp://portal.example.com"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_Audit(t *testing.T) {
	if err := Validate(&Config{AuditEnabled: true, AuditRetention: 90 * 24 * time.Hour}); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if err := Validate(&Config{AuditRetention: 0}); err != nil {
		t.Fatalf("zero retention keeps events forever; Validate() = %v", err)
	}
	if err := Validate(&Config{AuditRetention: -time.Hour}); err == nil {
		t.Fatal("negative retention must be rejected")
	}
}

func TestValidate_LeaderElection(t *testing.T) {
	timed := func(mode string, lease, renew, retry time.Duration) *Config {
		return &Config{LeaderElection: mode, LeaderElectionName: "agentregistry-controllers",
			LeaderElectionLeaseDuration: lease, LeaderElectionRenewDeadline: renew, LeaderElectionRetryPeriod: retry}
	}
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"unset means none", &Config{}, false},
		{"none", &Config{LeaderElection: "none"}, false},
		{"postgres defaults", timed("postgres", 15*time.Second, 10*time.Second, 2*time.Second), false},
		{"kubernetes defaults", timed("kubernetes", 15*time.Second, 10*time.Second, 2*time.Second), false},
		{"unknown mechanism", timed("etcd", 15*time.Second, 10*time.Second, 2*time.Second), true},
		{"empty name", &Config{LeaderElection: "postgres", LeaderElectionLeaseDuration: 15 * time.Second, LeaderElectionRenewDeadline: 10 * time.Second, LeaderElectionRetryPeriod: 2 * time.Second}, true},
		{"renew not below lease", timed("postgres", 10*time.Second, 10*time.Second, 2*time.Second), true},
		{"retry not below renew", timed("kubernetes", 15*time.Second, 2*time.Second, 2*time.Second), true},
		{"zero retry", timed("postgres", 15*time.Second, 10*time.Second, 0), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_OpenBao(t *testing.T) {
	bao := func(mutate func(*Config)) *Config {
		c := &Config{SecretStore: "OpenBao", OpenBaoAddr: "https://openbao:8200", OpenBaoMount: "agentregistry",
			OpenBaoAuth: "kubernetes", OpenBaoRole: "agentregistry", OpenBaoTimeout: 10 * time.Second}
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"kubernetes auth", bao(nil), false},
		{"approle auth", bao(func(c *Config) {
			c.OpenBaoAuth, c.OpenBaoAppRoleRoleIDFile, c.OpenBaoAppRoleSecretIDFile = "approle", "/run/role-id", "/run/secret-id"
		}), false},
		{"token auth", bao(func(c *Config) { c.OpenBaoAuth, c.OpenBaoTokenFile = "token", "/run/token" }), false},
		{"migrate from kubernetes", bao(func(c *Config) { c.SecretStoreMigrateFrom = "Kubernetes" }), false},
		{"no address", bao(func(c *Config) { c.OpenBaoAddr = "" }), true},
		{"address not a url", bao(func(c *Config) { c.OpenBaoAddr = "openbao:8200" }), true},
		{"empty mount", bao(func(c *Config) { c.OpenBaoMount = "" }), true},
		{"zero timeout", bao(func(c *Config) { c.OpenBaoTimeout = 0 }), true},
		{"kubernetes without a role", bao(func(c *Config) { c.OpenBaoRole = "" }), true},
		{"approle without files", bao(func(c *Config) { c.OpenBaoAuth = "approle" }), true},
		{"token without a file", bao(func(c *Config) { c.OpenBaoAuth = "token" }), true},
		{"unknown auth", bao(func(c *Config) { c.OpenBaoAuth = "ldap" }), true},
		{"migrate from itself", bao(func(c *Config) { c.SecretStoreMigrateFrom = "OpenBao" }), true},
		{"migrate from unknown", bao(func(c *Config) { c.SecretStoreMigrateFrom = "S3" }), true},
		{"migrate without a store", &Config{SecretStoreMigrateFrom: "Kubernetes"}, true},
		{"other stores ignore OpenBao settings", &Config{SecretStore: "Kubernetes"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
