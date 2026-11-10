package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

var logger = logging.New("jwt-authn")

const (
	// DefaultKeyRefreshInterval is the minimum time between forced JWKS
	// fetches for one issuer, triggered by an unknown key ID or a failed
	// fetch.
	DefaultKeyRefreshInterval = 30 * time.Second

	// maxTokenBytes rejects oversized tokens before any parsing.
	maxTokenBytes = 16 << 10

	defaultHTTPTimeout = 10 * time.Second
	discoveryPath      = "/.well-known/openid-configuration"
	maxDiscoveryBytes  = 1 << 20
)

// Option configures a Provider.
type Option func(*Provider)

// WithHTTPClient sets the client used for OIDC discovery and JWKS fetches.
func WithHTTPClient(c *http.Client) Option {
	return func(p *Provider) {
		if c != nil {
			p.client = c
		}
	}
}

// WithClock sets the time source used to validate exp, nbf and iat and to
// rate-limit key refreshes.
func WithClock(now func() time.Time) Option {
	return func(p *Provider) {
		if now != nil {
			p.now = now
		}
	}
}

// WithKeyRefreshInterval sets the minimum time between forced JWKS fetches
// per issuer. Defaults to DefaultKeyRefreshInterval.
func WithKeyRefreshInterval(d time.Duration) Option {
	return func(p *Provider) {
		p.minRefresh = d
	}
}

// Provider authenticates bearer JWTs against a fixed set of trusted issuers.
// It implements auth.AuthnProvider.
type Provider struct {
	issuers    map[string]*issuerState
	skew       time.Duration
	client     *http.Client
	now        func() time.Time
	minRefresh time.Duration
	cache      *jwk.Cache
}

var _ auth.AuthnProvider = (*Provider)(nil)

// issuerState holds the per-issuer key location and refresh bookkeeping.
type issuerState struct {
	cfg IssuerConfig

	mu          sync.Mutex
	jwksURI     string    // resolved JWKS URI; empty until discovered
	fetched     bool      // the JWKS has been fetched successfully at least once
	lastAttempt time.Time // last discovery, failed initial fetch, or forced refresh
}

// NewProvider returns a Provider trusting issuers. Issuers are validated and
// defaulted as by ParseIssuers. ctx bounds the lifetime of the background
// JWKS refresher. clockSkew is the leeway applied to exp, nbf and iat.
func NewProvider(ctx context.Context, issuers []IssuerConfig, clockSkew time.Duration, opts ...Option) (*Provider, error) {
	if len(issuers) == 0 {
		return nil, errors.New("at least one issuer is required")
	}
	if clockSkew < 0 {
		return nil, errors.New("clock skew must be non-negative")
	}
	p := &Provider{
		issuers:    make(map[string]*issuerState, len(issuers)),
		skew:       clockSkew,
		client:     &http.Client{Timeout: defaultHTTPTimeout},
		now:        time.Now,
		minRefresh: DefaultKeyRefreshInterval,
	}
	for _, opt := range opts {
		opt(p)
	}
	p.cache = jwk.NewCache(ctx)
	for i := range issuers {
		cfg := issuers[i]
		cfg.Audiences = append([]string(nil), cfg.Audiences...)
		if err := cfg.normalize(); err != nil {
			return nil, fmt.Errorf("issuer %d: %w", i, err)
		}
		if _, dup := p.issuers[cfg.Issuer]; dup {
			return nil, fmt.Errorf("issuer %d: duplicate issuer %q", i, cfg.Issuer)
		}
		st := &issuerState{cfg: cfg}
		if cfg.JWKSURI != "" {
			if err := p.register(cfg.JWKSURI); err != nil {
				return nil, fmt.Errorf("issuer %q: %w", cfg.Issuer, err)
			}
			st.jwksURI = cfg.JWKSURI
		}
		p.issuers[cfg.Issuer] = st
	}
	return p, nil
}

// Authenticate verifies the request's bearer token. Every failure wraps
// auth.ErrUnauthenticated.
func (p *Provider) Authenticate(ctx context.Context, reqHeaders func(name string) string, query url.Values) (auth.Session, error) {
	if query.Has("access_token") {
		return nil, unauthenticated("bearer tokens are not accepted in the query string")
	}
	token, err := bearerToken(reqHeaders("Authorization"))
	if err != nil {
		return nil, err
	}
	return p.verify(ctx, token)
}

// bearerToken extracts the token from an Authorization header value.
func bearerToken(header string) (string, error) {
	if header == "" {
		return "", unauthenticated("missing authorization header")
	}
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", unauthenticated("authorization scheme must be Bearer")
	}
	token = strings.TrimSpace(token)
	switch {
	case token == "":
		return "", unauthenticated("empty bearer token")
	case len(token) > maxTokenBytes:
		return "", unauthenticated("bearer token too large")
	case strings.ContainsAny(token, " \t"):
		return "", unauthenticated("malformed bearer token")
	}
	return token, nil
}

// verify checks the token's signature and claims and builds the session.
func (p *Provider) verify(ctx context.Context, token string) (*Session, error) {
	if strings.Count(token, ".") != 2 {
		return nil, unauthenticated("token is not a compact JWS")
	}
	raw := []byte(token)
	msg, err := jws.Parse(raw)
	if err != nil {
		return nil, unauthenticated("parsing token: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return nil, unauthenticated("token must carry exactly one signature")
	}
	hdr := sigs[0].ProtectedHeaders()
	alg := hdr.Algorithm().String()
	kid := hdr.KeyID()

	// The issuer is read before verification only to pick the key set; it
	// is checked again below against the verified claims.
	unverified, err := jwxjwt.ParseInsecure(raw)
	if err != nil {
		return nil, unauthenticated("parsing token claims: %w", err)
	}
	st, ok := p.issuers[unverified.Issuer()]
	if !ok {
		return nil, unauthenticated("untrusted issuer %q", unverified.Issuer())
	}
	if !st.cfg.allowsAlgorithm(alg) {
		return nil, unauthenticated("algorithm %q is not allowed for issuer %q", alg, st.cfg.Issuer)
	}

	payload, err := p.verifySignature(ctx, st, raw, alg, kid)
	if err != nil {
		return nil, err
	}

	if err := jwxjwt.Validate(unverified,
		jwxjwt.WithIssuer(st.cfg.Issuer),
		jwxjwt.WithRequiredClaim(jwxjwt.ExpirationKey),
		jwxjwt.WithAcceptableSkew(p.skew),
		jwxjwt.WithClock(jwxjwt.ClockFunc(p.now)),
	); err != nil {
		return nil, unauthenticated("validating token claims: %w", err)
	}
	if !intersects(unverified.Audience(), st.cfg.Audiences) {
		return nil, unauthenticated("token audience is not accepted for issuer %q", st.cfg.Issuer)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, unauthenticated("decoding token claims: %w", err)
	}
	return newSession(&st.cfg, claims)
}

// verifySignature verifies raw against the issuer's keys and returns the
// signed payload. An unknown key ID triggers at most one rate-limited JWKS
// refresh.
func (p *Provider) verifySignature(ctx context.Context, st *issuerState, raw []byte, alg, kid string) ([]byte, error) {
	set, err := p.keySet(ctx, st)
	if err != nil {
		return nil, err
	}
	payload, found := verifyWithSet(set, raw, alg, kid)
	if payload != nil {
		return payload, nil
	}
	// Refresh when the key may have rotated: the kid is unknown, or the
	// token names no kid and no current key verifies it.
	if found && kid != "" {
		return nil, unauthenticated("invalid token signature")
	}
	set, ok := p.forceRefresh(ctx, st)
	if !ok {
		return nil, unauthenticated("no key matches the token for issuer %q", st.cfg.Issuer)
	}
	if payload, _ := verifyWithSet(set, raw, alg, kid); payload != nil {
		return payload, nil
	}
	return nil, unauthenticated("no key matches the token for issuer %q", st.cfg.Issuer)
}

// verifyWithSet tries every key in set that may have produced the token.
// found reports whether any key matched kid and alg.
func verifyWithSet(set jwk.Set, raw []byte, alg, kid string) (payload []byte, found bool) {
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok || !keyUsable(key, alg, kid) {
			continue
		}
		found = true
		if payload, err := jws.Verify(raw, jws.WithKey(jwa.SignatureAlgorithm(alg), key)); err == nil {
			return payload, true
		}
	}
	return nil, found
}

// keyUsable reports whether key may verify a token signed with alg and kid.
func keyUsable(key jwk.Key, alg, kid string) bool {
	if kid != "" && key.KeyID() != kid {
		return false
	}
	if a := key.Algorithm().String(); a != "" && a != alg {
		return false
	}
	if u := key.KeyUsage(); u != "" && u != string(jwk.ForSignature) {
		return false
	}
	switch key.KeyType() {
	case jwa.RSA:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case jwa.EC:
		return strings.HasPrefix(alg, "ES")
	case jwa.OKP:
		return alg == "EdDSA"
	default:
		return false
	}
}

// keySet returns the issuer's cached JWKS, discovering its location and
// fetching it on first use. Failures are retried at most once per refresh
// interval.
func (p *Provider) keySet(ctx context.Context, st *issuerState) (jwk.Set, error) {
	st.mu.Lock()
	if st.fetched {
		uri := st.jwksURI
		st.mu.Unlock()
		set, err := p.cache.Get(ctx, uri)
		if err != nil {
			return nil, unauthenticated("loading keys for issuer %q: %w", st.cfg.Issuer, err)
		}
		return set, nil
	}
	defer st.mu.Unlock()
	if !st.lastAttempt.IsZero() && p.now().Sub(st.lastAttempt) < p.minRefresh {
		return nil, unauthenticated("keys for issuer %q are unavailable", st.cfg.Issuer)
	}
	st.lastAttempt = p.now()
	if st.jwksURI == "" {
		uri, err := p.discoverJWKSURI(ctx, st.cfg.Issuer)
		if err != nil {
			logger.Warn("oidc discovery failed", "issuer", st.cfg.Issuer, "error", err)
			return nil, unauthenticated("discovering keys for issuer %q: %w", st.cfg.Issuer, err)
		}
		if err := p.register(uri); err != nil {
			return nil, unauthenticated("issuer %q: %w", st.cfg.Issuer, err)
		}
		st.jwksURI = uri
	}
	set, err := p.cache.Get(ctx, st.jwksURI)
	if err != nil {
		logger.Warn("jwks fetch failed", "issuer", st.cfg.Issuer, "jwks_uri", st.jwksURI, "error", err)
		return nil, unauthenticated("loading keys for issuer %q: %w", st.cfg.Issuer, err)
	}
	st.fetched = true
	return set, nil
}

// forceRefresh refetches the issuer's JWKS unless it was refreshed within
// the refresh interval.
func (p *Provider) forceRefresh(ctx context.Context, st *issuerState) (jwk.Set, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.jwksURI == "" || (!st.lastAttempt.IsZero() && p.now().Sub(st.lastAttempt) < p.minRefresh) {
		return nil, false
	}
	st.lastAttempt = p.now()
	set, err := p.cache.Refresh(ctx, st.jwksURI)
	if err != nil {
		logger.Warn("jwks refresh failed", "issuer", st.cfg.Issuer, "jwks_uri", st.jwksURI, "error", err)
		return nil, false
	}
	logger.Debug("jwks refreshed", "issuer", st.cfg.Issuer)
	return set, true
}

func (p *Provider) register(uri string) error {
	if p.cache.IsRegistered(uri) {
		return nil
	}
	if err := p.cache.Register(uri, jwk.WithHTTPClient(p.client)); err != nil {
		return fmt.Errorf("registering jwks uri: %w", err)
	}
	return nil
}

// discoverJWKSURI reads jwks_uri from the issuer's OpenID configuration.
func (p *Provider) discoverJWKSURI(ctx context.Context, issuer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+discoveryPath, nil)
	if err != nil {
		return "", fmt.Errorf("building discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching discovery document: unexpected status %d", resp.StatusCode)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryBytes))
	if err := dec.Decode(&doc); err != nil {
		return "", fmt.Errorf("decoding discovery document: %w", err)
	}
	if doc.Issuer != issuer {
		return "", fmt.Errorf("discovery document issuer %q does not match %q", doc.Issuer, issuer)
	}
	if err := validateURL(doc.JWKSURI); err != nil {
		return "", fmt.Errorf("discovery document jwks_uri %q: %w", doc.JWKSURI, err)
	}
	return doc.JWKSURI, nil
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// unauthenticated returns an error wrapping auth.ErrUnauthenticated. It must
// never be given the token itself.
func unauthenticated(format string, args ...any) error {
	return fmt.Errorf("%w: %w", auth.ErrUnauthenticated, fmt.Errorf(format, args...))
}
