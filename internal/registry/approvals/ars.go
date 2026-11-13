// Package approvals holds writes that need approval and applies them once
// approved. Whether a change needs approval, who approves it, and how many
// approvals it needs are decided by the AuthZEN PDP's policy, and the
// approval workflow runs in the PDP's access request service (OpenID AuthZEN
// Access Request and Approval Profile). The registry submits the request,
// follows it, and applies the reviewed document when it is approved.
package approvals

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

const maxARSResponse = 1 << 20

// Task states reported by the access request service.
const (
	TaskPending   = "pending"
	TaskApproved  = "approved"
	TaskDenied    = "denied"
	TaskExpired   = "expired"
	TaskCancelled = "cancelled"
	TaskFailed    = "failed"
)

// AccessRequest is the body of an access request submission.
type AccessRequest struct {
	Subject  authzen.Subject  `json:"subject"`
	Resource authzen.Resource `json:"resource"`
	Action   authzen.Action   `json:"action"`
	Context  authzen.Context  `json:"context,omitempty"`
	Denial   map[string]any   `json:"denial"`
	Callback *Callback        `json:"callback,omitempty"`
}

// Callback asks the service to POST to Endpoint when the task ends.
type Callback struct {
	Endpoint string   `json:"endpoint"`
	State    string   `json:"state,omitempty"`
	Events   []string `json:"events,omitempty"`
}

// Task is the service's view of a request.
type Task struct {
	ID             string         `json:"id"`
	Status         string         `json:"status"`
	StatusEndpoint string         `json:"status_endpoint"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
	Progress       map[string]any `json:"progress,omitempty"`
	Display        map[string]any `json:"display,omitempty"`
}

// TaskResponse is a task with, once approved, its result.
type TaskResponse struct {
	Task   Task `json:"task"`
	Result *struct {
		Mode     string `json:"mode"`
		Approval *struct {
			ID            string `json:"id"`
			ApprovedAt    string `json:"approved_at"`
			ApprovedUntil string `json:"approved_until"`
		} `json:"approval"`
	} `json:"result,omitempty"`
}

// ApprovalID returns the approval of an approved task, or "".
func (t TaskResponse) ApprovalID() string {
	if t.Result == nil || t.Result.Approval == nil {
		return ""
	}
	return t.Result.Approval.ID
}

// ProblemError is an RFC 9457 problem from the service.
type ProblemError struct {
	Status int
	Type   string
	Title  string
	Detail string
}

func (e *ProblemError) Error() string {
	msg := e.Title
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if t := strings.TrimPrefix(e.Type, "urn:openid:authzen:access-request:error:"); t != "" && t != "about:blank" {
		msg = t + ": " + msg
	}
	return fmt.Sprintf("access request service: HTTP %d %s", e.Status, msg)
}

// ErrNotFound is an unknown task.
var ErrNotFound = errors.New("access request not found")

// ARSClient calls the PDP's access request service: as the registry for
// submissions and status, and as the approver (their own token) for the
// approver API.
type ARSClient struct {
	pdp    *authzen.Client
	origin *url.URL
	tokens authzen.TokenSource
	http   *http.Client
}

// NewARSClient returns a client for the PDP at baseURL. tokens are the
// registry's own credentials, which the service's caller_auth accepts.
func NewARSClient(pdp *authzen.Client, baseURL string, tokens authzen.TokenSource, httpClient *http.Client) (*ARSClient, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("approvals: invalid PDP URL %q", baseURL)
	}
	if tokens == nil {
		return nil, errors.New("approvals: the registry needs credentials for the access request service")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &ARSClient{pdp: pdp, origin: u, tokens: tokens, http: httpClient}, nil
}

// Submit sends an access request. idempotencyKey makes a retry return the
// same task.
func (c *ARSClient) Submit(ctx context.Context, req AccessRequest, idempotencyKey string) (TaskResponse, error) {
	meta, err := c.pdp.Metadata(ctx)
	if err != nil {
		return TaskResponse{}, err
	}
	if meta.AccessRequestEndpoint == "" {
		return TaskResponse{}, errors.New("the PDP offers no access request endpoint")
	}
	var out TaskResponse
	header := http.Header{}
	if idempotencyKey != "" {
		header.Set("Idempotency-Key", idempotencyKey)
	}
	err = c.call(ctx, http.MethodPost, meta.AccessRequestEndpoint, c.registryToken, header, req, &out)
	return out, err
}

// Status reads a task by its status endpoint.
func (c *ARSClient) Status(ctx context.Context, statusEndpoint string) (TaskResponse, error) {
	var out TaskResponse
	err := c.call(ctx, http.MethodGet, statusEndpoint, c.registryToken, nil, nil, &out)
	return out, err
}

// Cancel cancels a pending task.
func (c *ARSClient) Cancel(ctx context.Context, statusEndpoint, reason string) (TaskResponse, error) {
	var out TaskResponse
	err := c.call(ctx, http.MethodPost, strings.TrimRight(statusEndpoint, "/")+"/cancel", c.registryToken, nil,
		map[string]any{"reason": reason}, &out)
	return out, err
}

// Admin calls the approver API (/access/v1/admin/...) with the approver's
// own token, so the service decides who they are and what they may do.
func (c *ARSClient) Admin(ctx context.Context, approverToken, method, path string, in, out any) error {
	token := func(context.Context) (string, error) { return approverToken, nil }
	return c.call(ctx, method, c.origin.String()+"/access/v1/admin/"+strings.TrimLeft(path, "/"), token, nil, in, out)
}

func (c *ARSClient) registryToken(ctx context.Context) (string, error) {
	return c.tokens.Token(ctx)
}

// call sends one request to the PDP's origin only: status endpoints come
// from the PDP's responses, and the registry's credentials must not follow
// them anywhere else.
func (c *ARSClient) call(ctx context.Context, method, target string, token func(context.Context) (string, error), header http.Header, in, out any) error {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != c.origin.Scheme || u.Host != c.origin.Host {
		return fmt.Errorf("approvals: refusing to call %q outside the PDP %s", target, c.origin.Host)
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("approvals: encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("approvals: build request: %w", err)
	}
	maps.Copy(req.Header, header)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	tok, err := token(ctx)
	if err != nil {
		return fmt.Errorf("approvals: credentials: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if id := authzen.RequestIDFrom(ctx); id != "" {
		req.Header.Set("X-Request-ID", id)
	}
	// Never follow a redirect with credentials.
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("approvals: %s %s: %w", method, u.Path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxARSResponse))
	if err != nil {
		return fmt.Errorf("approvals: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		p := &ProblemError{Status: resp.StatusCode, Title: http.StatusText(resp.StatusCode)}
		var body struct {
			Type   string `json:"type"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(raw, &body) == nil {
			p.Type, p.Detail = body.Type, body.Detail
			if body.Title != "" {
				p.Title = body.Title
			}
		}
		if resp.StatusCode == http.StatusNotFound {
			return errors.Join(ErrNotFound, p)
		}
		return p
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("approvals: decode response: %w", err)
		}
	}
	return nil
}
