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
			AuthMode:       AuthModeRequired,
			AuthIssuers:    `[{"issuer":"https://idp.example.com","audiences":["agentregistry"]}]`,
			AuthClockSkew:  30 * time.Second,
			AuthzenURL:     "https://pdp.example.com",
			AuthzenTimeout: time.Second,
			AuthzenListMax: 1000,
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
		{"required without issuers", required(func(c *Config) { c.AuthIssuers = "" }), true},
		{"required without pdp", required(func(c *Config) { c.AuthzenURL = "" }), true},
		{"negative clock skew", required(func(c *Config) { c.AuthClockSkew = -time.Second }), true},
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
