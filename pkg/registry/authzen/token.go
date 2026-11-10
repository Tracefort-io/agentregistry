package authzen

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// TokenSource supplies the bearer token the PEP presents to the PDP. An
// empty token sends no Authorization header.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed bearer token.
type StaticToken string

// Token returns the fixed token.
func (t StaticToken) Token(context.Context) (string, error) {
	return string(t), nil
}

// ClientCredentialsConfig configures an OAuth 2.0 client-credentials grant.
type ClientCredentialsConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// HTTPClient is used for the token endpoint; nil uses http.DefaultClient.
	HTTPClient *http.Client
}

type clientCredentialsSource struct {
	ts oauth2.TokenSource
}

// NewClientCredentialsTokenSource returns a TokenSource that obtains and
// caches access tokens with the OAuth 2.0 client-credentials grant,
// refreshing them shortly before they expire.
func NewClientCredentialsTokenSource(cfg ClientCredentialsConfig) (TokenSource, error) {
	if cfg.TokenURL == "" || cfg.ClientID == "" {
		return nil, errors.New("authzen: client credentials require a token URL and client ID")
	}
	cc := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenURL,
		Scopes:       cfg.Scopes,
	}
	// The oauth2 token source keeps this context for every refresh, so it
	// must not be request scoped; it only carries the HTTP client.
	base := context.Background()
	if cfg.HTTPClient != nil {
		base = context.WithValue(base, oauth2.HTTPClient, cfg.HTTPClient)
	}
	return &clientCredentialsSource{ts: cc.TokenSource(base)}, nil
}

// Token returns a valid access token.
func (s *clientCredentialsSource) Token(context.Context) (string, error) {
	tok, err := s.ts.Token()
	if err != nil {
		return "", fmt.Errorf("authzen: fetch client credentials token: %w", err)
	}
	return tok.AccessToken, nil
}

type requestIDKey struct{}

// WithRequestID stores the request ID that is sent to the PDP as the
// X-Request-ID header.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom returns the request ID stored by WithRequestID.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
