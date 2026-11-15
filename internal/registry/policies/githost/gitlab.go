package githost

import (
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// gitLab is a project on gitlab.com or a self-managed GitLab.
type gitLab struct {
	apiClient
	// project is the project's full path, for example "group/sub/repo".
	project string
	secret  []byte
}

type gitLabMergeRequest struct {
	IID          int       `json:"iid"`
	Title        string    `json:"title"`
	WebURL       string    `json:"web_url"`
	CreatedAt    time.Time `json:"created_at"`
	SourceBranch string    `json:"source_branch"`
	TargetBranch string    `json:"target_branch"`
	Author       struct {
		Username string `json:"username"`
	} `json:"author"`
}

func (m gitLabMergeRequest) pullRequest() PullRequest {
	return PullRequest{
		Number: m.IID, Title: m.Title, URL: m.WebURL, Author: m.Author.Username,
		HeadBranch: m.SourceBranch, BaseBranch: m.TargetBranch, CreatedAt: m.CreatedAt,
	}
}

func (g *gitLab) path(parts ...string) string {
	// The project path is one URL-encoded segment ("group%2Frepo").
	return escapedPath(append([]string{"projects", g.project}, parts...))
}

func (g *gitLab) client() apiClient {
	c := g.apiClient
	c.auth = func(r *http.Request, token string) { r.Header.Set("PRIVATE-TOKEN", token) }
	return c
}

func (g *gitLab) OpenPullRequest(ctx context.Context, pr NewPullRequest) (PullRequest, error) {
	var out gitLabMergeRequest
	in := map[string]any{
		"title": pr.Title, "description": pr.Body, "source_branch": pr.Head, "target_branch": pr.Base,
		"remove_source_branch": true,
	}
	if err := g.client().do(ctx, http.MethodPost, g.path("merge_requests"), nil, in, &out, nil); err != nil {
		return PullRequest{}, fmt.Errorf("open merge request: %w", err)
	}
	return out.pullRequest(), nil
}

func (g *gitLab) ListOpenPullRequests(ctx context.Context, base string) ([]PullRequest, error) {
	var all []PullRequest
	for page := 1; page <= maxPages; page++ {
		var mrs []gitLabMergeRequest
		q := url.Values{"state": {"opened"}, "target_branch": {base}, "per_page": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}}
		if err := g.client().do(ctx, http.MethodGet, g.path("merge_requests"), q, nil, &mrs, nil); err != nil {
			return nil, fmt.Errorf("list merge requests: %w", err)
		}
		for _, m := range mrs {
			all = append(all, m.pullRequest())
		}
		if len(mrs) < pageSize {
			break
		}
	}
	return all, nil
}

func (g *gitLab) ChangedFiles(ctx context.Context, number int) ([]string, error) {
	var paths []string
	for page := 1; page <= maxPages; page++ {
		var diffs []struct {
			OldPath string `json:"old_path"`
			NewPath string `json:"new_path"`
		}
		q := url.Values{"per_page": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}}
		if err := g.client().do(ctx, http.MethodGet, g.path("merge_requests", strconv.Itoa(number), "diffs"), q, nil, &diffs, nil); err != nil {
			return nil, fmt.Errorf("list files of merge request %d: %w", number, err)
		}
		for _, d := range diffs {
			paths = append(paths, d.NewPath)
			if d.OldPath != "" && d.OldPath != d.NewPath {
				paths = append(paths, d.OldPath)
			}
		}
		if len(diffs) < pageSize {
			break
		}
	}
	return paths, nil
}

// ParseWebhook checks X-Gitlab-Token against the secret and reports a
// "Merge Request Hook" whose action is "merge".
func (g *gitLab) ParseWebhook(header http.Header, body []byte) (MergeEvent, bool, error) {
	if len(g.secret) == 0 {
		return MergeEvent{}, false, fmt.Errorf("%w: no webhook secret is configured", ErrBadSignature)
	}
	if subtle.ConstantTimeCompare([]byte(header.Get("X-Gitlab-Token")), g.secret) != 1 {
		return MergeEvent{}, false, ErrBadSignature
	}
	if header.Get("X-Gitlab-Event") != "Merge Request Hook" {
		return MergeEvent{}, false, nil
	}
	var event struct {
		ObjectKind string `json:"object_kind"`
		Attrs      struct {
			IID             int    `json:"iid"`
			Action          string `json:"action"`
			TargetBranch    string `json:"target_branch"`
			MergeCommitSHA  string `json:"merge_commit_sha"`
			SquashCommitSHA string `json:"squash_commit_sha"`
			LastCommit      struct {
				ID string `json:"id"`
			} `json:"last_commit"`
		} `json:"object_attributes"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		return MergeEvent{}, false, fmt.Errorf("decode merge request event: %w", err)
	}
	a := event.Attrs
	if event.ObjectKind != "merge_request" || a.Action != "merge" {
		return MergeEvent{}, false, nil
	}
	// Fast-forward merges have no merge commit; the target then ends at the
	// squash commit, or at the merge request's last commit.
	commit := cmp.Or(a.MergeCommitSHA, a.SquashCommitSHA, a.LastCommit.ID)
	if commit == "" {
		return MergeEvent{}, false, nil
	}
	return MergeEvent{Number: a.IID, BaseBranch: a.TargetBranch, MergeCommit: commit}, true, nil
}
