// Package jwt authenticates requests carrying OAuth 2.0 bearer tokens in JWT
// form, issued by one or more trusted OpenID Connect providers.
package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
)

// Defaults applied by ParseIssuers to fields left empty.
const (
	DefaultSubjectClaim = "sub"
	DefaultRolesClaim   = "realm_access.roles"
	DefaultGroupsClaim  = "groups"
)

var (
	// DefaultAlgorithms are the signature algorithms accepted when an issuer
	// configures none.
	DefaultAlgorithms = []string{"RS256", "ES256"}

	// defaultUsernameClaims and defaultClientIDClaims are tried in order when
	// the issuer does not name a claim.
	defaultUsernameClaims = []string{"preferred_username", "upn", "email"}
	defaultClientIDClaims = []string{"azp", "client_id"}

	// supportedAlgorithms are the asymmetric JWS algorithms an issuer may
	// allow. "none" and the HMAC family are deliberately absent: a shared
	// secret cannot be published in a JWKS, and accepting HS* next to RSA keys
	// opens the door to algorithm-confusion attacks.
	supportedAlgorithms = map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"PS256": true, "PS384": true, "PS512": true,
		"ES256": true, "ES384": true, "ES512": true,
		"EdDSA": true,
	}
)

// IssuerConfig describes one trusted token issuer.
type IssuerConfig struct {
	// Issuer must equal the token's "iss" claim exactly. Required.
	Issuer string `json:"issuer"`
	// Audiences lists accepted "aud" values; the token must carry at least
	// one of them. Required.
	Audiences []string `json:"audiences"`
	// JWKSURI is where the signing keys are published. When empty it is
	// discovered from <issuer>/.well-known/openid-configuration.
	JWKSURI string `json:"jwksUri,omitempty"`
	// Algorithms lists accepted signature algorithms. Defaults to
	// DefaultAlgorithms. "none" and HS* are rejected.
	Algorithms []string `json:"algorithms,omitempty"`
	// SubjectClaim names the claim holding the subject. Defaults to "sub".
	SubjectClaim string `json:"subjectClaim,omitempty"`
	// UsernameClaim names the claim holding a display name. When empty,
	// "preferred_username", "upn" and "email" are tried in order.
	UsernameClaim string `json:"usernameClaim,omitempty"`
	// ClientIDClaim names the claim holding the OAuth client ID. When empty,
	// "azp" and "client_id" are tried in order.
	ClientIDClaim string `json:"clientIdClaim,omitempty"`
	// RolesClaim is a dotted path to the roles array. Defaults to
	// "realm_access.roles" (Keycloak); Entra ID uses "roles". Keycloak client
	// roles live at "resource_access.<client>.roles"; client IDs containing
	// dots are supported.
	RolesClaim string `json:"rolesClaim,omitempty"`
	// GroupsClaim is a dotted path to the groups array. Defaults to "groups".
	GroupsClaim string `json:"groupsClaim,omitempty"`
	// ClientSubjectClaim optionally names a claim whose presence with a truthy
	// value marks a client-credentials token. When empty, a token whose
	// subject equals its client ID is treated as a client token.
	ClientSubjectClaim string `json:"clientSubjectClaim,omitempty"`
}

// ParseIssuers decodes a JSON array of issuers, validates each and applies
// defaults.
func ParseIssuers(jsonText string) ([]IssuerConfig, error) {
	dec := json.NewDecoder(strings.NewReader(jsonText))
	dec.DisallowUnknownFields()
	var issuers []IssuerConfig
	if err := dec.Decode(&issuers); err != nil {
		return nil, fmt.Errorf("decoding issuers: %w", err)
	}
	if dec.More() {
		return nil, errors.New("decoding issuers: unexpected data after the JSON array")
	}
	if len(issuers) == 0 {
		return nil, errors.New("at least one issuer is required")
	}
	seen := make(map[string]bool, len(issuers))
	for i := range issuers {
		if err := issuers[i].normalize(); err != nil {
			return nil, fmt.Errorf("issuer %d: %w", i, err)
		}
		if seen[issuers[i].Issuer] {
			return nil, fmt.Errorf("issuer %d: duplicate issuer %q", i, issuers[i].Issuer)
		}
		seen[issuers[i].Issuer] = true
	}
	return issuers, nil
}

// LoadIssuers reads issuers from file when set, and otherwise from the
// inline JSON.
func LoadIssuers(inline, file string) ([]IssuerConfig, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("reading issuers file: %w", err)
		}
		inline = string(b)
	}
	if strings.TrimSpace(inline) == "" {
		return nil, errors.New("no issuers configured")
	}
	return ParseIssuers(inline)
}

// normalize validates c and fills in defaults.
func (c *IssuerConfig) normalize() error {
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	if err := validateURL(c.Issuer); err != nil {
		return fmt.Errorf("issuer %q: %w", c.Issuer, err)
	}
	if c.JWKSURI != "" {
		if err := validateURL(c.JWKSURI); err != nil {
			return fmt.Errorf("jwksUri %q: %w", c.JWKSURI, err)
		}
	}
	audiences := c.Audiences[:0]
	for _, a := range c.Audiences {
		if a = strings.TrimSpace(a); a != "" {
			audiences = append(audiences, a)
		}
	}
	if len(audiences) == 0 {
		return fmt.Errorf("issuer %q: at least one audience is required", c.Issuer)
	}
	c.Audiences = audiences

	if len(c.Algorithms) == 0 {
		c.Algorithms = append([]string(nil), DefaultAlgorithms...)
	}
	for _, alg := range c.Algorithms {
		if !supportedAlgorithms[alg] {
			return fmt.Errorf("issuer %q: algorithm %q is not allowed", c.Issuer, alg)
		}
	}
	if c.SubjectClaim == "" {
		c.SubjectClaim = DefaultSubjectClaim
	}
	if c.RolesClaim == "" {
		c.RolesClaim = DefaultRolesClaim
	}
	if c.GroupsClaim == "" {
		c.GroupsClaim = DefaultGroupsClaim
	}
	return nil
}

// validateURL requires an absolute http(s) URL. Plain http is allowed so
// that development setups and tests work; production issuers use https.
func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("must be an absolute http(s) URL")
	}
	return nil
}

func (c *IssuerConfig) usernameClaims() []string {
	if c.UsernameClaim != "" {
		return []string{c.UsernameClaim}
	}
	return defaultUsernameClaims
}

func (c *IssuerConfig) clientIDClaims() []string {
	if c.ClientIDClaim != "" {
		return []string{c.ClientIDClaim}
	}
	return defaultClientIDClaims
}

func (c *IssuerConfig) allowsAlgorithm(alg string) bool {
	return slices.Contains(c.Algorithms, alg)
}
