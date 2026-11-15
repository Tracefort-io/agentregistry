package githost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// gitHub is a repository on github.com or GitHub Enterprise Server.
type gitHub struct {
	apiClient
	owner, repo string
	secret      []byte
}

var gitHubHeaders = map[string]string{
	"Accept":               "application/vnd.github+json",
	"X-GitHub-Api-Version": "2022-11-28",
}

type gitHubPull struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
	Merged         bool   `json:"merged"`
	MergeCommitSHA string `json:"merge_commit_sha"`
}

func (p gitHubPull) pullRequest() PullRequest {
	return PullRequest{
		Number: p.Number, Title: p.Title, URL: p.HTMLURL, Author: p.User.Login,
		HeadBranch: p.Head.Ref, BaseBranch: p.Base.Ref, CreatedAt: p.CreatedAt,
	}
}

func (g *gitHub) path(parts ...string) string {
	return escapedPath(append([]string{"repos", g.owner, g.repo}, parts...))
}

func (g *gitHub) client() apiClient {
	c := g.apiClient
	c.auth = func(r *http.Request, token string) { r.Header.Set("Authorization", "Bearer "+token) }
	return c
}

func (g *gitHub) OpenPullRequest(ctx context.Context, pr NewPullRequest) (PullRequest, error) {
	var out gitHubPull
	in := map[string]any{"title": pr.Title, "body": pr.Body, "head": pr.Head, "base": pr.Base}
	if err := g.client().do(ctx, http.MethodPost, g.path("pulls"), nil, in, &out, gitHubHeaders); err != nil {
		return PullRequest{}, fmt.Errorf("open pull request: %w", err)
	}
	return out.pullRequest(), nil
}

func (g *gitHub) ListOpenPullRequests(ctx context.Context, base string) ([]PullRequest, error) {
	var all []PullRequest
	for page := 1; page <= maxPages; page++ {
		var pulls []gitHubPull
		q := url.Values{"state": {"open"}, "base": {base}, "per_page": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}}
		if err := g.client().do(ctx, http.MethodGet, g.path("pulls"), q, nil, &pulls, gitHubHeaders); err != nil {
			return nil, fmt.Errorf("list pull requests: %w", err)
		}
		for _, p := range pulls {
			all = append(all, p.pullRequest())
		}
		if len(pulls) < pageSize {
			break
		}
	}
	return all, nil
}

func (g *gitHub) ChangedFiles(ctx context.Context, number int) ([]string, error) {
	var paths []string
	for page := 1; page <= maxPages; page++ {
		var files []struct {
			Filename         string `json:"filename"`
			PreviousFilename string `json:"previous_filename"`
		}
		q := url.Values{"per_page": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}}
		if err := g.client().do(ctx, http.MethodGet, g.path("pulls", strconv.Itoa(number), "files"), q, nil, &files, gitHubHeaders); err != nil {
			return nil, fmt.Errorf("list files of pull request %d: %w", number, err)
		}
		for _, f := range files {
			paths = append(paths, f.Filename)
			if f.PreviousFilename != "" {
				paths = append(paths, f.PreviousFilename)
			}
		}
		if len(files) < pageSize {
			break
		}
	}
	return paths, nil
}

// ParseWebhook checks X-Hub-Signature-256 (HMAC-SHA256 of the body) and
// reports a "pull_request" event closed by a merge.
func (g *gitHub) ParseWebhook(header http.Header, body []byte) (MergeEvent, bool, error) {
	if len(g.secret) == 0 {
		return MergeEvent{}, false, fmt.Errorf("%w: no webhook secret is configured", ErrBadSignature)
	}
	sig, ok := strings.CutPrefix(header.Get("X-Hub-Signature-256"), "sha256=")
	got, err := hex.DecodeString(sig)
	if !ok || err != nil {
		return MergeEvent{}, false, ErrBadSignature
	}
	mac := hmac.New(sha256.New, g.secret)
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return MergeEvent{}, false, ErrBadSignature
	}
	if header.Get("X-GitHub-Event") != "pull_request" {
		return MergeEvent{}, false, nil
	}
	var event struct {
		Action      string     `json:"action"`
		PullRequest gitHubPull `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		return MergeEvent{}, false, fmt.Errorf("decode pull_request event: %w", err)
	}
	pr := event.PullRequest
	if event.Action != "closed" || !pr.Merged || pr.MergeCommitSHA == "" {
		return MergeEvent{}, false, nil
	}
	return MergeEvent{Number: pr.Number, BaseBranch: pr.Base.Ref, MergeCommit: pr.MergeCommitSHA}, true, nil
}
