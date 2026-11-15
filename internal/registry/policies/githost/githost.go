// Package githost talks to the GitHub and GitLab APIs for what git itself
// can't do: pull (merge) requests and their webhooks. Reading and writing
// repository content goes through pkg/gitutil.
package githost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Providers.
const (
	ProviderGitHub = "github"
	ProviderGitLab = "gitlab"
)

const (
	maxResponseBytes = 4 << 20
	maxErrorRunes    = 512
	pageSize         = 100
	// maxPages bounds one listing (GitHub lists at most 3000 files per pull request).
	maxPages = 30
)

var (
	// ErrBadSignature is a webhook whose signature or token doesn't match.
	ErrBadSignature = errors.New("webhook signature does not match")
	// ErrNotFound is a pull request or repository the host doesn't know.
	ErrNotFound = errors.New("not found on the git host")
)

// PullRequest is a GitHub pull request or a GitLab merge request.
type PullRequest struct {
	Number     int       `json:"number"`
	Title      string    `json:"title"`
	URL        string    `json:"url"`
	Author     string    `json:"author"`
	HeadBranch string    `json:"headBranch"`
	BaseBranch string    `json:"baseBranch"`
	CreatedAt  time.Time `json:"createdAt"`
}

// NewPullRequest is a pull request to open from Head into Base.
type NewPullRequest struct {
	Title string
	Body  string
	Head  string
	Base  string
}

// MergeEvent is a pull request merged into BaseBranch as MergeCommit.
type MergeEvent struct {
	Number      int
	BaseBranch  string
	MergeCommit string
}

// Host is one repository on GitHub or GitLab.
type Host interface {
	OpenPullRequest(ctx context.Context, pr NewPullRequest) (PullRequest, error)
	// ListOpenPullRequests returns the open pull requests into base.
	ListOpenPullRequests(ctx context.Context, base string) ([]PullRequest, error)
	// ChangedFiles returns the paths a pull request adds, changes or
	// deletes; a rename yields both its old and new paths.
	ChangedFiles(ctx context.Context, number int) ([]string, error)
	// ParseWebhook checks a webhook delivery's signature and returns the
	// merge it reports; ok is false for any other event.
	ParseWebhook(header http.Header, body []byte) (event MergeEvent, ok bool, err error)
}

// Config selects and authenticates a Host.
type Config struct {
	// Provider is ProviderGitHub or ProviderGitLab.
	Provider string
	// RepoURL is the repository's clone URL (https://host/<path>.git).
	RepoURL string
	// APIURL overrides the API base URL derived from RepoURL.
	APIURL string
	// Token authenticates API calls.
	Token string
	// WebhookSecret checks webhook deliveries.
	WebhookSecret []byte
	// HTTPClient defaults to a client with a 30s timeout.
	HTTPClient *http.Client
}

// New returns the Host for cfg.Provider.
func New(cfg Config) (Host, error) {
	u, err := url.Parse(cfg.RepoURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid repository URL %q", cfg.RepoURL)
	}
	repoPath := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	if strings.Count(repoPath, "/") < 1 {
		return nil, fmt.Errorf("repository URL %q has no <namespace>/<repo> path", cfg.RepoURL)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	api := func(defaultURL string) (*url.URL, error) {
		raw := cfg.APIURL
		if raw == "" {
			raw = defaultURL
		}
		base, err := url.Parse(strings.TrimSuffix(raw, "/"))
		if err != nil || base.Host == "" {
			return nil, fmt.Errorf("invalid API URL %q", raw)
		}
		return base, nil
	}
	c := apiClient{http: client, token: cfg.Token}
	switch cfg.Provider {
	case ProviderGitHub:
		defaultAPI := u.Scheme + "://" + u.Host + "/api/v3"
		if u.Host == "github.com" {
			defaultAPI = "https://api.github.com"
		}
		base, err := api(defaultAPI)
		if err != nil {
			return nil, err
		}
		owner, repo, _ := strings.Cut(repoPath, "/")
		if strings.Contains(repo, "/") {
			return nil, fmt.Errorf("GitHub repository URL %q must be <owner>/<repo>", cfg.RepoURL)
		}
		c.base = base
		return &gitHub{apiClient: c, owner: owner, repo: repo, secret: cfg.WebhookSecret}, nil
	case ProviderGitLab:
		base, err := api(u.Scheme + "://" + u.Host + "/api/v4")
		if err != nil {
			return nil, err
		}
		c.base = base
		return &gitLab{apiClient: c, project: repoPath, secret: cfg.WebhookSecret}, nil
	default:
		return nil, fmt.Errorf("unsupported git host provider %q (want %q or %q)", cfg.Provider, ProviderGitHub, ProviderGitLab)
	}
}

// apiClient sends JSON requests to a host's REST API.
type apiClient struct {
	http  *http.Client
	base  *url.URL
	token string
	// auth sets the token on a request.
	auth func(*http.Request, string)
}

// do sends a request to path (escaped, relative to the API base) and
// decodes a 2xx JSON response into out.
func (c apiClient) do(ctx context.Context, method, path string, query url.Values, in, out any, headers map[string]string) error {
	u := *c.base
	u.RawPath = c.base.EscapedPath() + path
	u.Path, _ = url.PathUnescape(u.RawPath)
	u.RawQuery = query.Encode()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.auth != nil && c.token != "" {
		c.auth(req, c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, u.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%s %s: reading response: %w", method, u.Path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s %s: %w", method, u.Path, ErrNotFound)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := string(data)
		if c.token != "" {
			msg = strings.ReplaceAll(msg, c.token, "xxxxx")
		}
		return fmt.Errorf("%s %s: %s: %s", method, u.Path, resp.Status, truncate(msg))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decoding response: %w", method, u.Path, err)
	}
	return nil
}

// escapedPath joins segments into a path, escaping each one.
func escapedPath(segments []string) string {
	var b strings.Builder
	for _, s := range segments {
		b.WriteString("/")
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxErrorRunes {
		return string(r[:maxErrorRunes]) + "..."
	}
	return s
}
