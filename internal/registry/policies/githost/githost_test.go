package githost

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const token = "glpat-secret-token"

// fakeAPI records requests and answers them from handlers keyed by
// "METHOD escaped-path".
type fakeAPI struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []map[string]any
	handlers map[string]func(w http.ResponseWriter, r *http.Request)
}

func newFakeAPI(t *testing.T, handlers map[string]func(w http.ResponseWriter, r *http.Request)) (*fakeAPI, string) {
	f := &fakeAPI{handlers: handlers}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.requests = append(f.requests, r)
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		h, ok := f.handlers[r.Method+" "+r.URL.EscapedPath()]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// paged answers page N of total items made by item.
func paged(total int, item func(i int) any) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		out := []any{}
		for i := (page - 1) * perPage; i < min(page*perPage, total); i++ {
			out = append(out, item(i))
		}
		writeJSON(w, out)
	}
}

func TestNew(t *testing.T) {
	for _, tt := range []struct {
		name    string
		cfg     Config
		wantAPI string
		wantErr string
	}{
		{name: "github.com", cfg: Config{Provider: ProviderGitHub, RepoURL: "https://github.com/acme/policies.git"}, wantAPI: "https://api.github.com"},
		{name: "github enterprise", cfg: Config{Provider: ProviderGitHub, RepoURL: "https://ghe.acme.io/sec/policies.git"}, wantAPI: "https://ghe.acme.io/api/v3"},
		{name: "gitlab nested", cfg: Config{Provider: ProviderGitLab, RepoURL: "https://gitlab.acme.io/sec/opa/policies.git"}, wantAPI: "https://gitlab.acme.io/api/v4"},
		{name: "api override", cfg: Config{Provider: ProviderGitLab, RepoURL: "https://gitlab.com/a/b.git", APIURL: "https://proxy.acme.io/gl/api/v4/"}, wantAPI: "https://proxy.acme.io/gl/api/v4"},
		{name: "github nested path", cfg: Config{Provider: ProviderGitHub, RepoURL: "https://github.com/a/b/c.git"}, wantErr: "must be <owner>/<repo>"},
		{name: "no repo path", cfg: Config{Provider: ProviderGitHub, RepoURL: "https://github.com/acme"}, wantErr: "no <namespace>/<repo> path"},
		{name: "unknown provider", cfg: Config{Provider: "bitbucket", RepoURL: "https://bitbucket.org/a/b.git"}, wantErr: "unsupported git host provider"},
	} {
		h, err := New(tt.cfg)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%s: error = %v, want %q", tt.name, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		var base string
		switch h := h.(type) {
		case *gitHub:
			base = h.base.String()
		case *gitLab:
			base = h.base.String()
		}
		if base != tt.wantAPI {
			t.Errorf("%s: API base = %q, want %q", tt.name, base, tt.wantAPI)
		}
	}
}

func TestGitHubAPI(t *testing.T) {
	api, url := newFakeAPI(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/v3/repos/acme/policies/pulls": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]any{
				"number": 7, "title": "authzen: deny", "html_url": "https://ghe/acme/policies/pull/7",
				"created_at": "2026-11-14T09:00:00Z", "user": map[string]any{"login": "agentregistry-bot"},
				"head": map[string]any{"ref": "policy/authzen/x"}, "base": map[string]any{"ref": "main"},
			})
		},
		"GET /api/v3/repos/acme/policies/pulls": paged(150, func(i int) any {
			return map[string]any{"number": i + 1, "base": map[string]any{"ref": "main"}}
		}),
		"GET /api/v3/repos/acme/policies/pulls/7/files": paged(101, func(i int) any {
			if i == 0 {
				return map[string]any{"filename": "authzen/new.rego", "previous_filename": "authzen/old.rego"}
			}
			return map[string]any{"filename": fmt.Sprintf("other/f%d.rego", i)}
		}),
	})
	h, err := New(Config{Provider: ProviderGitHub, RepoURL: url + "/acme/policies.git", APIURL: url + "/api/v3", Token: token})
	if err != nil {
		t.Fatal(err)
	}

	pr, err := h.OpenPullRequest(t.Context(), NewPullRequest{Title: "authzen: deny", Body: "why", Head: "policy/authzen/x", Base: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Number != 7 || pr.URL != "https://ghe/acme/policies/pull/7" || pr.Author != "agentregistry-bot" ||
		pr.HeadBranch != "policy/authzen/x" || pr.BaseBranch != "main" || pr.CreatedAt.IsZero() {
		t.Fatalf("OpenPullRequest = %+v", pr)
	}
	req, body := api.requests[0], api.bodies[0]
	if req.Header.Get("Authorization") != "Bearer "+token || req.Header.Get("X-GitHub-Api-Version") == "" ||
		req.Header.Get("Accept") != "application/vnd.github+json" {
		t.Fatalf("headers = %v", req.Header)
	}
	if body["title"] != "authzen: deny" || body["head"] != "policy/authzen/x" || body["base"] != "main" || body["body"] != "why" {
		t.Fatalf("body = %v", body)
	}

	pulls, err := h.ListOpenPullRequests(t.Context(), "main")
	if err != nil || len(pulls) != 150 {
		t.Fatalf("ListOpenPullRequests = %d pulls, %v; want 150 over two pages", len(pulls), err)
	}
	if q := api.requests[1].URL.Query(); q.Get("state") != "open" || q.Get("base") != "main" {
		t.Fatalf("list query = %v", q)
	}

	files, err := h.ChangedFiles(t.Context(), 7)
	if err != nil || len(files) != 102 || files[0] != "authzen/new.rego" || files[1] != "authzen/old.rego" {
		t.Fatalf("ChangedFiles = %d %v, %v", len(files), files[:min(3, len(files))], err)
	}
}

func TestGitLabAPI(t *testing.T) {
	api, url := newFakeAPI(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/v4/projects/sec%2Fopa%2Fpolicies/merge_requests": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]any{
				"iid": 3, "title": "authzen: deny", "web_url": "https://gl/sec/opa/policies/-/merge_requests/3",
				"created_at": "2026-11-14T09:00:00Z", "author": map[string]any{"username": "ar-bot"},
				"source_branch": "policy/authzen/x", "target_branch": "main",
			})
		},
		"GET /api/v4/projects/sec%2Fopa%2Fpolicies/merge_requests": paged(2, func(i int) any {
			return map[string]any{"iid": i + 1, "target_branch": "main"}
		}),
		"GET /api/v4/projects/sec%2Fopa%2Fpolicies/merge_requests/3/diffs": paged(2, func(i int) any {
			if i == 0 {
				return map[string]any{"old_path": "authzen/old.rego", "new_path": "authzen/new.rego"}
			}
			return map[string]any{"old_path": "authzen/data.json", "new_path": "authzen/data.json"}
		}),
	})
	h, err := New(Config{Provider: ProviderGitLab, RepoURL: url + "/sec/opa/policies.git", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mr, err := h.OpenPullRequest(t.Context(), NewPullRequest{Title: "authzen: deny", Body: "why", Head: "policy/authzen/x", Base: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if mr.Number != 3 || mr.Author != "ar-bot" || mr.HeadBranch != "policy/authzen/x" || mr.BaseBranch != "main" {
		t.Fatalf("OpenPullRequest = %+v", mr)
	}
	if api.requests[0].Header.Get("PRIVATE-TOKEN") != token || api.requests[0].Header.Get("Authorization") != "" {
		t.Fatalf("headers = %v", api.requests[0].Header)
	}
	if b := api.bodies[0]; b["source_branch"] != "policy/authzen/x" || b["target_branch"] != "main" || b["description"] != "why" {
		t.Fatalf("body = %v", b)
	}
	mrs, err := h.ListOpenPullRequests(t.Context(), "main")
	if err != nil || len(mrs) != 2 {
		t.Fatalf("ListOpenPullRequests = %v, %v", mrs, err)
	}
	if q := api.requests[1].URL.Query(); q.Get("state") != "opened" || q.Get("target_branch") != "main" {
		t.Fatalf("list query = %v", q)
	}
	files, err := h.ChangedFiles(t.Context(), 3)
	if err != nil || !slices.Equal(files, []string{"authzen/new.rego", "authzen/old.rego", "authzen/data.json"}) {
		t.Fatalf("ChangedFiles = %v, %v", files, err)
	}
}

func TestAPIErrors(t *testing.T) {
	_, url := newFakeAPI(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/v3/repos/acme/policies/pulls": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"Validation Failed: token `+token+` `+strings.Repeat("x", 2000)+`"}`, http.StatusUnprocessableEntity)
		},
	})
	h, err := New(Config{Provider: ProviderGitHub, RepoURL: url + "/acme/policies.git", APIURL: url + "/api/v3", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.OpenPullRequest(t.Context(), NewPullRequest{Title: "t", Head: "h", Base: "main"})
	if err == nil || !strings.Contains(err.Error(), "422") || strings.Contains(err.Error(), token) || len(err.Error()) > 800 {
		t.Fatalf("error = %v, want a bounded 422 without the token", err)
	}
	if _, err := h.ChangedFiles(t.Context(), 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing pull request: error = %v, want ErrNotFound", err)
	}
}

func gitHubSignature(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGitHubWebhook(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	merged := `{"action":"closed","pull_request":{"number":7,"merged":true,"merge_commit_sha":"abc123","base":{"ref":"main"}}}`
	closed := `{"action":"closed","pull_request":{"number":8,"merged":false,"base":{"ref":"main"}}}`
	opened := `{"action":"opened","pull_request":{"number":9,"base":{"ref":"main"}}}`
	for _, tt := range []struct {
		name, event, body, sig string
		secret                 string
		want                   MergeEvent
		wantOK                 bool
		wantErr                error
	}{
		{name: "merged", event: "pull_request", body: merged, sig: gitHubSignature(secret, merged), want: MergeEvent{Number: 7, BaseBranch: "main", MergeCommit: "abc123"}, wantOK: true},
		{name: "closed unmerged", event: "pull_request", body: closed, sig: gitHubSignature(secret, closed)},
		{name: "opened", event: "pull_request", body: opened, sig: gitHubSignature(secret, opened)},
		{name: "ping", event: "ping", body: `{"zen":"x"}`, sig: gitHubSignature(secret, `{"zen":"x"}`)},
		{name: "wrong secret", event: "pull_request", body: merged, sig: gitHubSignature("other", merged), wantErr: ErrBadSignature},
		{name: "tampered body", event: "pull_request", body: merged + " ", sig: gitHubSignature(secret, merged), wantErr: ErrBadSignature},
		{name: "missing signature", event: "pull_request", body: merged, wantErr: ErrBadSignature},
		{name: "sha1 signature", event: "pull_request", body: merged, sig: "sha1=abcd", wantErr: ErrBadSignature},
		{name: "no secret configured", event: "pull_request", body: merged, sig: gitHubSignature("", merged), secret: "-", wantErr: ErrBadSignature},
	} {
		s := secret
		if tt.secret == "-" {
			s = ""
		}
		h, _ := New(Config{Provider: ProviderGitHub, RepoURL: "https://github.com/acme/policies.git", WebhookSecret: []byte(s)})
		header := http.Header{"X-Github-Event": {tt.event}}
		if tt.sig != "" {
			header.Set("X-Hub-Signature-256", tt.sig)
		}
		got, ok, err := h.ParseWebhook(header, []byte(tt.body))
		if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) || ok != tt.wantOK || got != tt.want {
			t.Errorf("%s: ParseWebhook = %+v, %v, %v; want %+v, %v, %v", tt.name, got, ok, err, tt.want, tt.wantOK, tt.wantErr)
		}
	}
}

func TestGitLabWebhook(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	event := func(action, merge, squash, last string) string {
		return fmt.Sprintf(`{"object_kind":"merge_request","object_attributes":{"iid":3,"action":%q,"target_branch":"main",`+
			`"merge_commit_sha":%q,"squash_commit_sha":%q,"last_commit":{"id":%q}}}`, action, merge, squash, last)
	}
	for _, tt := range []struct {
		name, kind, body, token string
		want                    MergeEvent
		wantOK                  bool
		wantErr                 error
	}{
		{name: "merge commit", kind: "Merge Request Hook", body: event("merge", "m1", "s1", "l1"), token: secret, want: MergeEvent{Number: 3, BaseBranch: "main", MergeCommit: "m1"}, wantOK: true},
		{name: "squash fast-forward", kind: "Merge Request Hook", body: event("merge", "", "s1", "l1"), token: secret, want: MergeEvent{Number: 3, BaseBranch: "main", MergeCommit: "s1"}, wantOK: true},
		{name: "fast-forward", kind: "Merge Request Hook", body: event("merge", "", "", "l1"), token: secret, want: MergeEvent{Number: 3, BaseBranch: "main", MergeCommit: "l1"}, wantOK: true},
		{name: "opened", kind: "Merge Request Hook", body: event("open", "", "", "l1"), token: secret},
		{name: "push hook", kind: "Push Hook", body: `{"object_kind":"push"}`, token: secret},
		{name: "wrong token", kind: "Merge Request Hook", body: event("merge", "m1", "", ""), token: "nope", wantErr: ErrBadSignature},
		{name: "no token", kind: "Merge Request Hook", body: event("merge", "m1", "", ""), wantErr: ErrBadSignature},
	} {
		h, _ := New(Config{Provider: ProviderGitLab, RepoURL: "https://gitlab.com/sec/policies.git", WebhookSecret: []byte(secret)})
		header := http.Header{"X-Gitlab-Event": {tt.kind}}
		if tt.token != "" {
			header.Set("X-Gitlab-Token", tt.token)
		}
		got, ok, err := h.ParseWebhook(header, []byte(tt.body))
		if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) || ok != tt.wantOK || got != tt.want {
			t.Errorf("%s: ParseWebhook = %+v, %v, %v; want %+v, %v, %v", tt.name, got, ok, err, tt.want, tt.wantOK, tt.wantErr)
		}
	}
	h, _ := New(Config{Provider: ProviderGitLab, RepoURL: "https://gitlab.com/sec/policies.git"})
	if _, _, err := h.ParseWebhook(http.Header{"X-Gitlab-Token": {""}}, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("no secret configured: error = %v, want ErrBadSignature", err)
	}
}
