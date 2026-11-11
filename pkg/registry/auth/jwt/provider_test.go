package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

const testAudience = "agentregistry"

var testNow = time.Unix(1_800_000_000, 0)

// signingKey is a private key with its JWK form.
type signingKey struct {
	alg     jwa.SignatureAlgorithm
	private jwk.Key
	public  jwk.Key
	raw     any
}

func newRSAKey(t *testing.T, kid string) signingKey {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return newSigningKey(t, raw, jwa.RS256, kid)
}

func newECKey(t *testing.T, kid string) signingKey {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return newSigningKey(t, raw, jwa.ES256, kid)
}

func newSigningKey(t *testing.T, raw any, alg jwa.SignatureAlgorithm, kid string) signingKey {
	t.Helper()
	priv, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, kid))
	pub, err := jwk.PublicKeyOf(priv)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyUsageKey, jwk.ForSignature))
	return signingKey{alg: alg, private: priv, public: pub, raw: raw}
}

// sign produces a compact JWS over claims.
func (k signingKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.KeyIDKey, k.private.KeyID()))
	out, err := jws.Sign(payload, jws.WithKey(k.alg, k.private, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(out)
}

// idp is a test identity provider serving discovery and a mutable JWKS.
type idp struct {
	server    *httptest.Server
	mu        sync.Mutex
	keys      []jwk.Key
	jwksHits  atomic.Int32
	discovery atomic.Int32
}

func newIDP(t *testing.T, keys ...jwk.Key) *idp {
	t.Helper()
	i := &idp{keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		i.jwksHits.Add(1)
		i.mu.Lock()
		set := jwk.NewSet()
		for _, k := range i.keys {
			_ = set.AddKey(k)
		}
		i.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		i.discovery.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   i.issuer(),
			"jwks_uri": i.server.URL + "/jwks",
		})
	})
	i.server = httptest.NewServer(mux)
	t.Cleanup(i.server.Close)
	return i
}

func (i *idp) issuer() string  { return i.server.URL }
func (i *idp) jwksURI() string { return i.server.URL + "/jwks" }

func (i *idp) setKeys(keys ...jwk.Key) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = keys
}

// fakeClock is a settable time source.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestProvider(t *testing.T, clock *fakeClock, skew time.Duration, issuers ...IssuerConfig) *Provider {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p, err := NewProvider(ctx, issuers, skew, WithClock(clock.Now))
	require.NoError(t, err)
	return p
}

func baseClaims(iss string) map[string]any {
	return map[string]any{
		"iss": iss,
		"sub": "user-1",
		"aud": testAudience,
		"exp": testNow.Add(time.Hour).Unix(),
		"iat": testNow.Unix(),
	}
}

func with(claims map[string]any, kv ...any) map[string]any {
	out := make(map[string]any, len(claims))
	maps.Copy(out, claims)
	for i := 0; i+1 < len(kv); i += 2 {
		k := kv[i].(string)
		if kv[i+1] == nil {
			delete(out, k)
			continue
		}
		out[k] = kv[i+1]
	}
	return out
}

func authenticate(p *Provider, header string, query url.Values) (auth.Session, error) {
	return p.Authenticate(context.Background(), func(name string) string {
		if name == "Authorization" {
			return header
		}
		return ""
	}, query)
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestProviderAuthenticate(t *testing.T) {
	rsaKey := newRSAKey(t, "rsa-1")
	ecKey := newECKey(t, "ec-1")
	strangerKey := newRSAKey(t, "rsa-1") // same kid, different key
	provider := newIDP(t, rsaKey.public, ecKey.public)
	other := newIDP(t, strangerKey.public)
	clock := &fakeClock{now: testNow}
	p := newTestProvider(t, clock, 30*time.Second,
		IssuerConfig{Issuer: provider.issuer(), Audiences: []string{testAudience, "other"}, JWKSURI: provider.jwksURI()},
		IssuerConfig{Issuer: other.issuer(), Audiences: []string{testAudience}, JWKSURI: other.jwksURI()},
	)
	iss := provider.issuer()
	claims := baseClaims(iss)

	// HS256 signed with the issuer's RSA public key as the HMAC secret.
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.raw.(*rsa.PrivateKey).PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	hsHdrs := jws.NewHeaders()
	require.NoError(t, hsHdrs.Set(jws.KeyIDKey, "rsa-1"))
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	hsToken, err := jws.Sign(claimsJSON, jws.WithKey(jwa.HS256, pubPEM, jws.WithProtectedHeaders(hsHdrs)))
	require.NoError(t, err)

	noneToken := b64(map[string]string{"alg": "none", "kid": "rsa-1"}) + "." + b64(claims) + "."

	tests := []struct {
		name    string
		header  string
		query   url.Values
		wantErr bool
	}{
		{"valid RS256", "Bearer " + rsaKey.sign(t, claims), nil, false},
		{"valid ES256", "Bearer " + ecKey.sign(t, claims), nil, false},
		{"scheme is case-insensitive", "bearer " + rsaKey.sign(t, claims), nil, false},
		{"audience list intersects", "Bearer " + rsaKey.sign(t, with(claims, "aud", []string{"x", "other"})), nil, false},
		{"expired", "Bearer " + rsaKey.sign(t, with(claims, "exp", testNow.Add(-time.Minute).Unix())), nil, true},
		{"expired within skew", "Bearer " + rsaKey.sign(t, with(claims, "exp", testNow.Add(-10*time.Second).Unix())), nil, false},
		{"nbf in future", "Bearer " + rsaKey.sign(t, with(claims, "nbf", testNow.Add(time.Minute).Unix())), nil, true},
		{"nbf within skew", "Bearer " + rsaKey.sign(t, with(claims, "nbf", testNow.Add(10*time.Second).Unix())), nil, false},
		{"iat in future", "Bearer " + rsaKey.sign(t, with(claims, "iat", testNow.Add(time.Minute).Unix())), nil, true},
		{"missing exp", "Bearer " + rsaKey.sign(t, with(claims, "exp", nil)), nil, true},
		{"missing sub", "Bearer " + rsaKey.sign(t, with(claims, "sub", nil)), nil, true},
		{"wrong audience", "Bearer " + rsaKey.sign(t, with(claims, "aud", "someone-else")), nil, true},
		{"missing audience", "Bearer " + rsaKey.sign(t, with(claims, "aud", nil)), nil, true},
		{"unknown issuer", "Bearer " + rsaKey.sign(t, with(claims, "iss", "https://evil.example")), nil, true},
		{"issuer with trailing slash", "Bearer " + rsaKey.sign(t, with(claims, "iss", iss+"/")), nil, true},
		{"signed by another trusted issuer's key", "Bearer " + strangerKey.sign(t, claims), nil, true},
		{"wrong issuer claim for key", "Bearer " + rsaKey.sign(t, with(claims, "iss", other.issuer())), nil, true},
		{"alg none", "Bearer " + noneToken, nil, true},
		{"HS256 with RSA public key as secret", "Bearer " + string(hsToken), nil, true},
		{"missing header", "", nil, true},
		{"basic scheme", "Basic dXNlcjpwYXNz", nil, true},
		{"empty bearer", "Bearer ", nil, true},
		{"bearer without space", "Bearer" + rsaKey.sign(t, claims), nil, true},
		{"garbage token", "Bearer not.a.jwt", nil, true},
		{"two-part token", "Bearer abc.def", nil, true},
		{"token in query string", "", url.Values{"access_token": {rsaKey.sign(t, claims)}}, true},
		{"token in query string with valid header", "Bearer " + rsaKey.sign(t, claims), url.Values{"access_token": {"x"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := authenticate(p, tt.header, tt.query)
			if tt.wantErr {
				require.Error(t, err)
				t.Logf("rejected: %v", err)
				require.ErrorIs(t, err, auth.ErrUnauthenticated, "error %v must wrap ErrUnauthenticated", err)
				require.Nil(t, sess)
				return
			}
			require.NoError(t, err)
			pr := sess.Principal()
			require.Equal(t, "user-1", pr.Subject)
			require.Equal(t, iss, pr.Issuer)
			require.True(t, pr.IsAuthenticated())
			require.Equal(t, iss, pr.Claims["iss"])
		})
	}
}

func TestProviderKeyRotation(t *testing.T) {
	oldKey := newRSAKey(t, "old")
	newKey := newRSAKey(t, "new")
	thirdKey := newRSAKey(t, "third")
	server := newIDP(t, oldKey.public)
	clock := &fakeClock{now: testNow}
	p := newTestProvider(t, clock, 0, IssuerConfig{
		Issuer: server.issuer(), Audiences: []string{testAudience}, JWKSURI: server.jwksURI(),
	})
	claims := baseClaims(server.issuer())

	_, err := authenticate(p, "Bearer "+oldKey.sign(t, claims), nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, server.jwksHits.Load())

	// The IdP rotates. Within the refresh interval of the initial fetch an
	// unknown kid does not trigger a fetch.
	server.setKeys(oldKey.public, newKey.public)
	_, err = authenticate(p, "Bearer "+newKey.sign(t, claims), nil)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.EqualValues(t, 1, server.jwksHits.Load())

	// After the interval the unknown kid triggers one refresh and is accepted.
	clock.Advance(DefaultKeyRefreshInterval)
	_, err = authenticate(p, "Bearer "+newKey.sign(t, claims), nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, server.jwksHits.Load())

	// Repeated unknown kids are rate limited: no fetch per request.
	server.setKeys(oldKey.public, newKey.public, thirdKey.public)
	for range 5 {
		_, err = authenticate(p, "Bearer "+thirdKey.sign(t, claims), nil)
		require.ErrorIs(t, err, auth.ErrUnauthenticated)
	}
	require.EqualValues(t, 2, server.jwksHits.Load())

	// A known kid with a bad signature never triggers a refresh.
	clock.Advance(DefaultKeyRefreshInterval)
	forged := newRSAKey(t, "new")
	_, err = authenticate(p, "Bearer "+forged.sign(t, claims), nil)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.EqualValues(t, 2, server.jwksHits.Load())

	_, err = authenticate(p, "Bearer "+thirdKey.sign(t, claims), nil)
	require.NoError(t, err)
	require.EqualValues(t, 3, server.jwksHits.Load())
}

// A key the IdP stops publishing, for example one that leaked, must stop
// verifying tokens once the key cache expires, however long the IdP's
// cache headers allow.
func TestProviderRemovedKeyExpires(t *testing.T) {
	oldKey := newRSAKey(t, "old")
	newKey := newRSAKey(t, "new")
	server := newIDP(t, oldKey.public)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p, err := NewProvider(ctx, []IssuerConfig{{
		Issuer: server.issuer(), Audiences: []string{testAudience}, JWKSURI: server.jwksURI(),
	}}, 0, WithClock(func() time.Time { return testNow }), WithKeyCacheTTL(time.Second))
	require.NoError(t, err)
	claims := baseClaims(server.issuer())
	token := "Bearer " + oldKey.sign(t, claims)

	_, err = authenticate(p, token, nil)
	require.NoError(t, err)

	server.setKeys(newKey.public)
	require.Eventually(t, func() bool {
		_, err := authenticate(p, token, nil)
		return errors.Is(err, auth.ErrUnauthenticated)
	}, 10*time.Second, 100*time.Millisecond, "a removed key is still trusted")
}

func TestProviderDiscovery(t *testing.T) {
	key := newECKey(t, "ec-1")
	server := newIDP(t, key.public)
	clock := &fakeClock{now: testNow}
	p := newTestProvider(t, clock, 0, IssuerConfig{
		Issuer: server.issuer(), Audiences: []string{testAudience}, Algorithms: []string{"ES256"},
	})

	for range 3 {
		sess, err := authenticate(p, "Bearer "+key.sign(t, baseClaims(server.issuer())), nil)
		require.NoError(t, err)
		require.Equal(t, server.issuer(), sess.Principal().Issuer)
	}
	require.EqualValues(t, 1, server.discovery.Load())
	require.EqualValues(t, 1, server.jwksHits.Load())
}

func TestProviderDiscoveryFailureIsRateLimited(t *testing.T) {
	key := newRSAKey(t, "rsa-1")
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	clock := &fakeClock{now: testNow}
	p := newTestProvider(t, clock, 0, IssuerConfig{Issuer: server.URL, Audiences: []string{testAudience}})

	for range 3 {
		_, err := authenticate(p, "Bearer "+key.sign(t, baseClaims(server.URL)), nil)
		require.ErrorIs(t, err, auth.ErrUnauthenticated)
	}
	require.EqualValues(t, 1, hits.Load())

	clock.Advance(DefaultKeyRefreshInterval)
	_, err := authenticate(p, "Bearer "+key.sign(t, baseClaims(server.URL)), nil)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.EqualValues(t, 2, hits.Load())
}

func TestProviderDisallowedAlgorithm(t *testing.T) {
	ecKey := newECKey(t, "ec-1")
	server := newIDP(t, ecKey.public)
	p := newTestProvider(t, &fakeClock{now: testNow}, 0, IssuerConfig{
		Issuer: server.issuer(), Audiences: []string{testAudience}, JWKSURI: server.jwksURI(), Algorithms: []string{"RS256"},
	})
	_, err := authenticate(p, "Bearer "+ecKey.sign(t, baseClaims(server.issuer())), nil)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.EqualValues(t, 0, server.jwksHits.Load(), "a disallowed algorithm must be refused before fetching keys")
}

func TestProviderPrincipal(t *testing.T) {
	key := newRSAKey(t, "rsa-1")
	keycloak := newIDP(t, key.public)
	entra := newIDP(t, key.public)
	p := newTestProvider(t, &fakeClock{now: testNow}, 0,
		IssuerConfig{Issuer: keycloak.issuer(), Audiences: []string{testAudience}, JWKSURI: keycloak.jwksURI()},
		IssuerConfig{
			Issuer: entra.issuer(), Audiences: []string{testAudience}, JWKSURI: entra.jwksURI(),
			RolesClaim: "roles", SubjectClaim: "oid", ClientSubjectClaim: "idtyp_app",
		},
	)

	tests := []struct {
		name       string
		claims     map[string]any
		want       auth.Principal
		wantClient bool
	}{
		{
			name: "keycloak user",
			claims: with(baseClaims(keycloak.issuer()),
				"preferred_username", "alice",
				"azp", "registry-ui",
				"realm_access", map[string]any{"roles": []any{"publisher", "reader"}},
				"groups", []any{"/team-a", "/team-b"},
			),
			want: auth.Principal{
				Subject: "user-1", Issuer: keycloak.issuer(), ClientID: "registry-ui", Username: "alice",
				Roles: []string{"publisher", "reader"}, Groups: []string{"/team-a", "/team-b"},
			},
		},
		{
			name: "keycloak client credentials",
			claims: with(baseClaims(keycloak.issuer()),
				"sub", "ci-bot", "client_id", "ci-bot",
				"realm_access", map[string]any{"roles": []any{"publisher"}},
			),
			want: auth.Principal{
				Subject: "ci-bot", Issuer: keycloak.issuer(), ClientID: "ci-bot",
				Roles: []string{"publisher"},
			},
			wantClient: true,
		},
		{
			name: "keycloak delegated",
			claims: with(baseClaims(keycloak.issuer()),
				"azp", "agent-a", "upn", "alice@example.com",
				"act", map[string]any{"sub": "agent-a", "iss": keycloak.issuer(), "act": map[string]any{"sub": "gateway"}},
			),
			want: auth.Principal{
				Subject: "user-1", Issuer: keycloak.issuer(), ClientID: "agent-a", Username: "alice@example.com",
				Actor: []auth.Actor{{Subject: "agent-a", Issuer: keycloak.issuer()}, {Subject: "gateway"}},
			},
		},
		{
			name: "entra user",
			claims: with(baseClaims(entra.issuer()),
				"sub", "pairwise-sub", "oid", "object-1", "azp", "app-1", "email", "bob@example.com",
				"roles", []any{"Registry.Admin"}, "groups", []any{"g-1"},
			),
			want: auth.Principal{
				Subject: "object-1", Issuer: entra.issuer(), ClientID: "app-1", Username: "bob@example.com",
				Roles: []string{"Registry.Admin"}, Groups: []string{"g-1"},
			},
		},
		{
			name: "entra app token marked by claim",
			claims: with(baseClaims(entra.issuer()),
				"oid", "sp-1", "azp", "app-2", "idtyp_app", true, "roles", []any{"Registry.Publish"},
			),
			want: auth.Principal{
				Subject: "sp-1", Issuer: entra.issuer(), ClientID: "app-2", Roles: []string{"Registry.Publish"},
			},
			wantClient: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := authenticate(p, "Bearer "+key.sign(t, tt.claims), nil)
			require.NoError(t, err)
			got := sess.Principal()
			require.NotEmpty(t, got.Claims)
			got.Claims = nil
			require.Equal(t, tt.wantClient, got.IsClient)
			got.IsClient = false
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNewProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		issuers []IssuerConfig
		skew    time.Duration
		opts    []Option
	}{
		{"no issuers", nil, 0, nil},
		{"negative skew", []IssuerConfig{{Issuer: "https://idp.example", Audiences: []string{"a"}}}, -time.Second, nil},
		{"no audience", []IssuerConfig{{Issuer: "https://idp.example"}}, 0, nil},
		{"HS256", []IssuerConfig{{Issuer: "https://idp.example", Audiences: []string{"a"}, Algorithms: []string{"HS256"}}}, 0, nil},
		{"duplicate", []IssuerConfig{
			{Issuer: "https://idp.example", Audiences: []string{"a"}},
			{Issuer: "https://idp.example", Audiences: []string{"b"}},
		}, 0, nil},
		{"key cache TTL under 1s", []IssuerConfig{{Issuer: "https://idp.example", Audiences: []string{"a"}}}, 0,
			[]Option{WithKeyCacheTTL(500 * time.Millisecond)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewProvider(context.Background(), tt.issuers, tt.skew, tt.opts...)
			require.Error(t, err)
		})
	}
}
