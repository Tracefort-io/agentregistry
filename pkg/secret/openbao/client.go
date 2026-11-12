// Package openbao stores Secret payloads in OpenBao's KV version 2 engine.
// The registry keeps only a Secret's metadata and key names; values live in
// OpenBao, where its policies decide who may read them and its audit log
// records every access.
//
// The client speaks OpenBao's HTTP API directly (it is Vault-compatible):
// login, token renewal, and KV reads, writes and deletes.
package openbao

import (
	"bytes"
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
)

const (
	maxResponseBytes = 4 << 20
	// renewWhenLeft renews a token once less than this share of its TTL is left.
	renewWhenLeft = 3
)

var (
	// ErrNotFound is a 404 from OpenBao.
	ErrNotFound = errors.New("openbao: not found")
	// ErrForbidden is a 403 that a fresh login did not fix: the policy does
	// not allow the operation.
	ErrForbidden = errors.New("openbao: permission denied")
)

// Login is the result of authenticating to OpenBao.
type Login struct {
	Token     string
	TTL       time.Duration
	Renewable bool
}

// Auth obtains a token.
type Auth interface {
	Login(ctx context.Context, c *Client) (Login, error)
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// Address is OpenBao's base URL, for example https://openbao:8200.
	Address string
	// Namespace is an OpenBao namespace; empty for the root.
	Namespace string
	Auth      Auth
	// HTTPClient carries the timeout and TLS settings.
	HTTPClient *http.Client
	// Now is the clock (tests).
	Now func() time.Time
}

// Client calls OpenBao with a token it obtains and renews itself.
type Client struct {
	base      *url.URL
	namespace string
	auth      Auth
	http      *http.Client
	now       func() time.Time

	mu        sync.Mutex
	token     string
	expires   time.Time // zero: does not expire
	ttl       time.Duration
	renewable bool
}

// NewClient validates cfg and returns a Client. It does not log in yet.
func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.Address, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("openbao: address must be an http(s) URL, got %q", cfg.Address)
	}
	if cfg.Auth == nil {
		return nil, errors.New("openbao: an auth method is required")
	}
	c := &Client{base: u, namespace: cfg.Namespace, auth: cfg.Auth, http: cfg.HTTPClient, now: cfg.Now}
	if c.http == nil {
		c.http = &http.Client{Timeout: 10 * time.Second}
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// apiError is a non-2xx answer. Its message holds OpenBao's own errors,
// which name paths and reasons, never values or tokens.
type apiError struct {
	status int
	msgs   []string
}

func (e *apiError) Error() string {
	msg := http.StatusText(e.status)
	if len(e.msgs) > 0 {
		msg = strings.Join(e.msgs, "; ")
	}
	return fmt.Sprintf("openbao: HTTP %d: %s", e.status, msg)
}

func (e *apiError) Unwrap() error {
	switch e.status {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusForbidden:
		return ErrForbidden
	}
	return nil
}

// Do calls path with the client's token, logging in or renewing first when
// needed. A 403 triggers one fresh login and retry, since OpenBao answers a
// revoked or expired token with 403 too. out, when not nil, receives the
// JSON response.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	token, err := c.currentToken(ctx)
	if err != nil {
		return err
	}
	err = c.raw(ctx, method, path, token, in, out)
	if !errors.Is(err, ErrForbidden) {
		return err
	}
	c.forget(token)
	if token, err = c.currentToken(ctx); err != nil {
		return err
	}
	return c.raw(ctx, method, path, token, in, out)
}

// Unauthenticated calls path without a token (login endpoints).
func (c *Client) Unauthenticated(ctx context.Context, method, path string, in, out any) error {
	return c.raw(ctx, method, path, "", in, out)
}

func (c *Client) raw(ctx context.Context, method, path, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("openbao: encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+"/v1/"+path, body)
	if err != nil {
		return fmt.Errorf("openbao: build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("openbao: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("openbao: read response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return errors.New("openbao: response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		return &apiError{status: resp.StatusCode, msgs: e.Errors}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("openbao: decode response: %w", err)
	}
	return nil
}

// currentToken returns a usable token: the cached one, renewed when most of
// its TTL has passed, or a fresh login.
func (c *Client) currentToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.token != "" {
		if c.expires.IsZero() || now.Before(c.expires.Add(-c.ttl/renewWhenLeft)) {
			return c.token, nil
		}
		if c.renewable && now.Before(c.expires) {
			if err := c.renewLocked(ctx); err == nil {
				return c.token, nil
			}
		}
	}
	login, err := c.auth.Login(ctx, c)
	if err != nil {
		return "", fmt.Errorf("openbao: login: %w", err)
	}
	if login.Token == "" {
		return "", errors.New("openbao: login returned no token")
	}
	c.setLocked(login, now)
	return c.token, nil
}

func (c *Client) renewLocked(ctx context.Context) error {
	var resp authResponse
	if err := c.raw(ctx, http.MethodPost, "auth/token/renew-self", c.token, map[string]any{}, &resp); err != nil {
		return err
	}
	c.setLocked(resp.login(), c.now())
	return nil
}

func (c *Client) setLocked(l Login, now time.Time) {
	c.token, c.ttl, c.renewable = l.Token, l.TTL, l.Renewable
	c.expires = time.Time{}
	if l.TTL > 0 {
		c.expires = now.Add(l.TTL)
	}
}

// forget drops token if it is still the cached one, so the next call logs in.
func (c *Client) forget(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		c.token = ""
	}
}

// authResponse is the "auth" block of a login or renewal.
type authResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int64  `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

func (r authResponse) login() Login {
	if r.Auth == nil {
		return Login{}
	}
	return Login{Token: r.Auth.ClientToken, TTL: time.Duration(r.Auth.LeaseDuration) * time.Second, Renewable: r.Auth.Renewable}
}
