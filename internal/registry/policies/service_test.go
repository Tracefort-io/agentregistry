package policies

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/githost"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/opaeval"
	"github.com/agentregistry-dev/agentregistry/pkg/gitutil"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

type fixture struct {
	repo  *fakeRepo
	host  *fakeHost
	authz *fakeAuthz
	audit *recorder
	svc   *Service
	// v1, head are commits of the seeded repository.
	v1, head string
}

func newFixture(t *testing.T, mutate ...func(*Config)) *fixture {
	t.Helper()
	repo := newFakeRepo()
	v1 := repo.add(map[string]string{
		"README.md":             "policies",
		"authzen/registry.rego": "package authzen\n\ndefault allow := false\n",
		"authzen/data.json":     `{"approvers":[]}`,
	}, "seed")
	head := repo.add(map[string]string{
		"README.md":                  "policies",
		"authzen/registry.rego":      "package authzen\n\ndefault allow := true\n",
		"authzen/registry_test.rego": "package authzen_test\n",
		"authzen/data.json":          `{"approvers":[]}`,
		"authzen/roles/data.json":    `{"admins": []}`,
		"system/authz.rego":          "package system.authz\n",
		"docs/notes.md":              "no rego here",
		"Bad_Dir/x.rego":             "package bad\n",
	}, "allow by default")
	repo.refs["refs/heads/main"] = head
	repo.refs["refs/tags/authzen/v1"] = v1
	repo.refs["refs/tags/authzen/v2"] = head
	repo.refs["refs/tags/authzen/vnext"] = head // not a version
	host := &fakeHost{files: map[int][]string{}}
	f := &fixture{repo: repo, host: host, authz: &fakeAuthz{}, audit: &recorder{}, v1: v1, head: head}
	cfg := Config{
		Open:       func(context.Context) (GitRepo, githost.Host, error) { return repo, host, nil },
		Branch:     "main",
		Authorizer: f.authz,
		Committer:  gitutil.Signature{Name: "agentregistry", Email: "agentregistry@acme.io"},
		Audit:      f.audit,
		Now:        func() time.Time { return time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC) },
	}
	for _, m := range mutate {
		m(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

func TestList(t *testing.T) {
	f := newFixture(t)
	f.authz.allow = map[string]bool{"read policy/authzen": true}
	got, err := f.svc.List(adaCtx())
	if err != nil {
		t.Fatal(err)
	}
	// system is forbidden, docs has no Rego, Bad_Dir is not a policy name.
	if len(got) != 1 {
		t.Fatalf("List = %+v, want only authzen", got)
	}
	a := got[0]
	if a.Name != "authzen" || a.Files != 4 || a.LatestVersion != "v2" ||
		!slices.Equal(a.Packages, []string{"authzen", "authzen_test"}) ||
		!slices.Equal(a.DataPaths, []string{"data.authzen", "data.authzen.roles"}) {
		t.Fatalf("summary = %+v", a)
	}
	if !slices.Contains(f.authz.calls, "read policy/system") {
		t.Fatalf("system was not checked: %v", f.authz.calls)
	}
}

func TestGet(t *testing.T) {
	f := newFixture(t)
	for _, tt := range []struct {
		name, policy, ref string
		wantCommit        string
		wantFiles         int
		wantErr           error
	}{
		{name: "branch head", policy: "authzen", wantCommit: f.head, wantFiles: 4},
		{name: "version", policy: "authzen", ref: "v1", wantCommit: f.v1, wantFiles: 2},
		{name: "commit", policy: "authzen", ref: f.v1, wantCommit: f.v1, wantFiles: 2},
		{name: "new policy at head is empty", policy: "newpol", wantCommit: f.head, wantFiles: 0},
		{name: "unknown version", policy: "authzen", ref: "v9", wantErr: ErrNotFound},
		{name: "policy absent at ref", policy: "system", ref: "v1", wantErr: ErrNotFound},
		{name: "invalid name", policy: "../etc", wantErr: ErrInvalid},
	} {
		p, err := f.svc.Get(adaCtx(), tt.policy, tt.ref)
		if tt.wantErr != nil {
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("%s: error = %v, want %v", tt.name, err, tt.wantErr)
			}
			continue
		}
		if err != nil || p.Commit != tt.wantCommit || len(p.Files) != tt.wantFiles {
			t.Errorf("%s: Get = commit %s, %d files, %v; want %s, %d", tt.name, p.Commit, len(p.Files), err, tt.wantCommit, tt.wantFiles)
		}
	}
	p, _ := f.svc.Get(adaCtx(), "authzen", "")
	if p.Ref != "main" || p.Files[0].Path != "data.json" || p.LatestVersion != "v2" {
		t.Fatalf("Get(head) = %+v", p)
	}

	f.authz.allow = map[string]bool{}
	if _, err := f.svc.Get(adaCtx(), "authzen", ""); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("forbidden Get: error = %v", err)
	}
}

func TestVersionsAndDiff(t *testing.T) {
	f := newFixture(t)
	for i := 3; i <= 10; i++ {
		f.repo.refs["refs/tags/authzen/v"+strconv.Itoa(i)] = f.head
	}
	versions, err := f.svc.Versions(adaCtx(), "authzen")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 10 || versions[0].Version != "v10" || versions[9].Version != "v1" ||
		versions[9].Commit != f.v1 || versions[9].Message != "seed" || versions[9].Author != "Seed" {
		t.Fatalf("Versions = %+v", versions)
	}

	changes, err := f.svc.Diff(adaCtx(), "authzen", "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, c := range changes {
		paths = append(paths, c.Path)
	}
	if !slices.Equal(paths, []string{"registry.rego", "registry_test.rego", "roles/data.json"}) {
		t.Fatalf("Diff paths = %v", paths)
	}
	if changes[1].Old != nil || changes[1].New == nil || !strings.Contains(*changes[0].Old, "false") {
		t.Fatalf("Diff = %+v", changes)
	}
}

func TestPending(t *testing.T) {
	f := newFixture(t)
	f.host.open = []githost.PullRequest{{Number: 1}, {Number: 2}, {Number: 3}}
	f.host.files = map[int][]string{1: {"authzen/registry.rego"}, 2: {"system/authz.rego"}, 3: {"authzenx/a.rego", "README.md"}}
	got, err := f.svc.Pending(adaCtx(), "authzen")
	if err != nil || len(got) != 1 || got[0].Number != 1 {
		t.Fatalf("Pending = %+v, %v; want only #1", got, err)
	}
}

func TestPublish(t *testing.T) {
	checker := &fakeChecker{}
	f := newFixture(t, func(c *Config) { c.Checker = checker })
	res, err := f.svc.Publish(adaCtx(), "authzen", PublishRequest{
		BaseCommit: f.head,
		Files: map[string]*string{
			"registry.rego":      new("package authzen\n\ndefault allow := false\n"),
			"roles/data.json":    nil,
			"extra/helpers.rego": new("package authzen.helpers\n"),
		},
		Message: "authzen: deny by default\n\nAllowing everything was a mistake.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.repo.commits) != 1 {
		t.Fatalf("commits = %d", len(f.repo.commits))
	}
	c := f.repo.commits[0]
	if c.Base != f.head || !strings.HasPrefix(c.Branch, "policy/authzen/20261114-093000-") || c.Branch != res.Branch {
		t.Fatalf("commit request = %+v", c)
	}
	if c.Author.Name != "ada" || c.Author.Email != "ada@acme.io" || c.Committer.Name != "agentregistry" || c.Committer.When.IsZero() {
		t.Fatalf("signatures = %+v / %+v", c.Author, c.Committer)
	}
	if !strings.Contains(c.Message, "Allowing everything was a mistake.") ||
		!strings.Contains(c.Message, "Published-by: u-ada (https://idp.acme.io/realms/acme)") {
		t.Fatalf("message = %q", c.Message)
	}
	if c.Files["authzen/roles/data.json"] != nil || string(c.Files["authzen/extra/helpers.rego"]) != "package authzen.helpers\n" || len(c.Files) != 3 {
		t.Fatalf("files = %v", c.Files)
	}
	// The checker saw the policy as it will be after the change.
	if _, ok := checker.got["roles/data.json"]; ok || string(checker.got["registry.rego"]) != "package authzen\n\ndefault allow := false\n" ||
		checker.got["registry_test.rego"] == nil || checker.got["extra/helpers.rego"] == nil {
		t.Fatalf("checker saw %v", checker.got)
	}
	pr := f.host.opened[0]
	if pr.Title != "authzen: deny by default" || pr.Base != "main" || pr.Head != c.Branch ||
		!strings.Contains(pr.Body, "Allowing everything was a mistake.") || !strings.Contains(pr.Body, "by ada") {
		t.Fatalf("pull request = %+v", pr)
	}
	if res.PullRequest.URL != "https://git/pr/41" {
		t.Fatalf("result = %+v", res)
	}
	e := f.audit.events[0]
	if e.Action != AuditActionPublish || e.Outcome != "success" || e.Detail != "https://git/pr/41" || e.Resource.Name != "authzen" || e.Resource.Kind != "Policy" {
		t.Fatalf("audit = %+v", e)
	}
	if !slices.Contains(f.authz.calls, "publish policy/authzen") {
		t.Fatalf("publish not authorized: %v", f.authz.calls)
	}
}

func TestPublishRefuses(t *testing.T) {
	ok := map[string]*string{"registry.rego": new("package authzen\n")}
	for _, tt := range []struct {
		name    string
		policy  string
		req     func(f *fixture) PublishRequest
		setup   func(f *fixture)
		wantErr error
		errText string
	}{
		{name: "no message", req: func(f *fixture) PublishRequest { return PublishRequest{BaseCommit: f.head, Files: ok} }, wantErr: ErrInvalid},
		{name: "no files", req: func(f *fixture) PublishRequest { return PublishRequest{BaseCommit: f.head, Message: "m"} }, wantErr: ErrInvalid},
		{name: "escaping path", req: func(f *fixture) PublishRequest {
			return PublishRequest{BaseCommit: f.head, Message: "m", Files: map[string]*string{"../system/authz.rego": new("x")}}
		}, wantErr: ErrInvalid},
		{name: "unclean path", req: func(f *fixture) PublishRequest {
			return PublishRequest{BaseCommit: f.head, Message: "m", Files: map[string]*string{"a//b.rego": new("x")}}
		}, wantErr: ErrInvalid},
		{name: "hidden file", req: func(f *fixture) PublishRequest {
			return PublishRequest{BaseCommit: f.head, Message: "m", Files: map[string]*string{".manifest.rego": new("x")}}
		}, wantErr: ErrInvalid},
		{name: "other file type", req: func(f *fixture) PublishRequest {
			return PublishRequest{BaseCommit: f.head, Message: "m", Files: map[string]*string{"run.sh": new("x")}}
		}, wantErr: ErrInvalid, errText: ".rego file or data.json"},
		{name: "too large", req: func(f *fixture) PublishRequest {
			return PublishRequest{BaseCommit: f.head, Message: "m", Files: map[string]*string{"a.rego": new(strings.Repeat("x", maxFileBytes+1))}}
		}, wantErr: ErrInvalid},
		{name: "no change", req: func(f *fixture) PublishRequest {
			return PublishRequest{BaseCommit: f.head, Message: "m", Files: map[string]*string{"data.json": new(`{"approvers":[]}`)}}
		}, wantErr: ErrConflict},
		{name: "bad name", policy: "Bad_Dir", req: func(f *fixture) PublishRequest {
			return PublishRequest{BaseCommit: f.head, Message: "m", Files: ok}
		}, wantErr: ErrInvalid},
		{name: "forbidden", setup: func(f *fixture) { f.authz.allow = map[string]bool{"read policy/authzen": true} },
			req: func(f *fixture) PublishRequest { return PublishRequest{BaseCommit: f.head, Message: "m", Files: ok} }, wantErr: auth.ErrForbidden},
		{name: "check fails", setup: func(f *fixture) {},
			req: func(f *fixture) PublishRequest { return PublishRequest{BaseCommit: f.head, Message: "m", Files: ok} }, wantErr: ErrInvalid, errText: "boom"},
	} {
		checker := &fakeChecker{}
		if tt.name == "check fails" {
			checker.err = errBoom
		}
		f := newFixture(t, func(c *Config) { c.Checker = checker })
		if tt.setup != nil {
			tt.setup(f)
		}
		_, err := f.svc.Publish(adaCtx(), cmp.Or(tt.policy, "authzen"), tt.req(f))
		if !errors.Is(err, tt.wantErr) || (tt.errText != "" && !strings.Contains(err.Error(), tt.errText)) {
			t.Errorf("%s: error = %v, want %v %q", tt.name, err, tt.wantErr, tt.errText)
		}
		if len(f.repo.commits) != 0 || len(f.host.opened) != 0 {
			t.Errorf("%s: refused publish still committed or opened a pull request", tt.name)
		}
	}
}

func TestPublishPullRequestFailure(t *testing.T) {
	f := newFixture(t)
	f.host.openErr = errBoom
	_, err := f.svc.Publish(adaCtx(), "authzen", PublishRequest{BaseCommit: f.head, Message: "m",
		Files: map[string]*string{"registry.rego": new("package authzen\n")}})
	if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "pushed branch policy/authzen/") {
		t.Fatalf("error = %v", err)
	}
	if e := f.audit.events[0]; e.Outcome != "failure" {
		t.Fatalf("audit = %+v", e)
	}
}

func TestOnMerged(t *testing.T) {
	f := newFixture(t)
	merge := f.repo.add(map[string]string{
		"authzen/registry.rego": "package authzen\n", "system/authz.rego": "package system.authz\n", "docs/notes.md": "x",
	}, "merge")
	f.host.files[7] = []string{"authzen/registry.rego", "system/authz.rego", "docs/notes.md", "README.md", "gone/x.rego"}
	event := githost.MergeEvent{Number: 7, BaseBranch: "main", MergeCommit: merge}

	if err := f.svc.OnMerged(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if f.repo.refs["refs/tags/authzen/v3"] != merge || f.repo.refs["refs/tags/system/v1"] != merge {
		t.Fatalf("tags = %v", f.repo.refs)
	}
	if _, ok := f.repo.refs["refs/tags/docs/v1"]; ok {
		t.Fatal("a directory without Rego was tagged")
	}
	if len(f.audit.events) != 2 || f.audit.events[0].Action != AuditActionTag || f.audit.events[0].Source != "webhook" {
		t.Fatalf("audit = %+v", f.audit.events)
	}

	// A redelivery changes nothing.
	if err := f.svc.OnMerged(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.repo.refs["refs/tags/authzen/v4"]; ok {
		t.Fatal("redelivery tagged again")
	}
	// Merges into other branches are ignored.
	if err := f.svc.OnMerged(context.Background(), githost.MergeEvent{Number: 7, BaseBranch: "dev", MergeCommit: f.v1}); err != nil {
		t.Fatal(err)
	}
	if len(f.audit.events) != 2 {
		t.Fatalf("audit after no-ops = %+v", f.audit.events)
	}
}

func TestOnMergedRace(t *testing.T) {
	f := newFixture(t)
	merge := f.repo.add(map[string]string{"authzen/registry.rego": "package authzen\n"}, "merge")
	f.host.files[8] = []string{"authzen/registry.rego"}
	// Another writer takes v3 between listing and pushing.
	f.repo.tagRace = map[string]string{"authzen/v3": f.v1}
	if err := f.svc.OnMerged(context.Background(), githost.MergeEvent{Number: 8, BaseBranch: "main", MergeCommit: merge}); err != nil {
		t.Fatal(err)
	}
	if f.repo.refs["refs/tags/authzen/v4"] != merge {
		t.Fatalf("tags = %v, want authzen/v4 at the merge", f.repo.refs)
	}
}

func TestWebhookHandler(t *testing.T) {
	f := newFixture(t)
	merge := f.repo.add(map[string]string{"authzen/registry.rego": "package authzen\n"}, "merge")
	f.host.files[9] = []string{"authzen/registry.rego"}
	h := f.svc.WebhookHandler()
	for _, tt := range []struct {
		name, method, secret, body string
		want                       int
	}{
		{name: "wrong method", method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "bad signature", method: http.MethodPost, secret: "nope", body: "merged 9 main " + merge, want: http.StatusUnauthorized},
		{name: "other event", method: http.MethodPost, secret: webhookSecret, body: "ping", want: http.StatusNoContent},
		{name: "merge", method: http.MethodPost, secret: webhookSecret, body: "merged 9 main " + merge, want: http.StatusNoContent},
	} {
		req := httptest.NewRequest(tt.method, "/policies/webhook", strings.NewReader(tt.body))
		req.Header.Set("X-Test-Secret", tt.secret)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
	if f.repo.refs["refs/tags/authzen/v3"] != merge {
		t.Fatalf("webhook did not tag: %v", f.repo.refs)
	}
}

func TestStatus(t *testing.T) {
	f := newFixture(t)
	// Nothing configured: unchecked.
	if st, err := f.svc.Status(adaCtx(), "authzen"); err != nil || st.Checked {
		t.Fatalf("Status without OPA = %+v, %v", st, err)
	}
	for _, tt := range []struct {
		name    string
		modules []string
		want    PolicyStatus
	}{
		{name: "latest version live", modules: []string{"package authzen\n\ndefault allow := true\n", "package authzen_test\n", "package other\n"},
			want: PolicyStatus{Checked: true, Loaded: true, LiveVersion: "v2", HeadLoaded: true}},
		{name: "older version live", modules: []string{"package authzen\n\ndefault allow := false\n"},
			want: PolicyStatus{Checked: true, Loaded: true, LiveVersion: "v1"}},
		{name: "test file missing", modules: []string{"package authzen\n\ndefault allow := true\n"},
			want: PolicyStatus{Checked: true}},
		{name: "nothing loaded", want: PolicyStatus{Checked: true}},
	} {
		f := newFixture(t, func(c *Config) { c.OPA = fakeOPA{modules: tt.modules} })
		st, err := f.svc.Status(adaCtx(), "authzen")
		if err != nil || st != tt.want {
			t.Errorf("%s: Status = %+v, %v; want %+v", tt.name, st, err, tt.want)
		}
	}
}

func TestAuthorEmail(t *testing.T) {
	for _, tt := range []struct {
		p    auth.Principal
		want string
	}{
		{p: ada, want: "ada@acme.io"},
		{p: auth.Principal{Subject: "u-1", Issuer: "https://idp.acme.io/realms/x", Username: "bob smith"}, want: "bob-smith@idp.acme.io"},
		{p: auth.Principal{Subject: "u-2", Issuer: "https://idp.acme.io", Claims: map[string]any{"email": "x <y@z>"}}, want: "u-2@idp.acme.io"},
		{p: auth.Principal{}, want: "anonymous@agentregistry"},
	} {
		if got := authorEmail(tt.p); got != tt.want {
			t.Errorf("authorEmail(%+v) = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestTools(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Engine = opaeval.New(time.Second) })
	f.authz.allow = map[string]bool{"read policy/authzen": true}
	draft := PolicyDraft{
		"registry.rego":      "package authzen\n\nallow if input.user in data.authzen.admins\n",
		"registry_test.rego": "package authzen_test\n\nimport data.authzen\n\ntest_ada if authzen.allow with input as {\"user\": \"ada\"}\n",
		"data.json":          `{"admins": ["ada"]}`,
	}

	formatted, err := f.svc.Format(adaCtx(), "authzen", "registry.rego", "package authzen\nallow if {input.x==1}")
	if err != nil || formatted.Content != "package authzen\n\nallow if input.x == 1\n" || len(formatted.Problems) != 0 {
		t.Fatalf("Format = %+v, %v", formatted, err)
	}
	probs, err := f.svc.CheckDraft(adaCtx(), "authzen", PolicyDraft{"registry.rego": "package authzen\n\nallow if x\n"})
	if err != nil || len(probs) != 1 || probs[0].File != "authzen/registry.rego" {
		t.Fatalf("CheckDraft = %+v, %v", probs, err)
	}
	res, err := f.svc.EvaluateDraft(adaCtx(), "authzen", draft, "data.authzen.allow", map[string]any{"user": "ada"}, nil)
	if err != nil || len(res.Result) != 1 || res.Result[0].Expressions[0].Value != true {
		t.Fatalf("EvaluateDraft = %+v, %v", res, err)
	}
	report, err := f.svc.TestDraft(adaCtx(), "authzen", draft, nil)
	if err != nil || report.Passed != 1 || report.Failed != 0 {
		t.Fatalf("TestDraft = %+v, %v", report, err)
	}

	// Tools need read on the policy, and only take the policy's own files.
	if _, err := f.svc.CheckDraft(adaCtx(), "system", draft); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("CheckDraft(system) error = %v, want forbidden", err)
	}
	if _, err := f.svc.Format(adaCtx(), "authzen", "../system/authz.rego", "package x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Format(escaping path) error = %v", err)
	}
	if _, err := f.svc.CheckDraft(adaCtx(), "authzen", PolicyDraft{"run.sh": "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CheckDraft(run.sh) error = %v", err)
	}

	// With an Engine, Publish refuses a draft that doesn't compile.
	f.authz.allow = nil
	_, err = f.svc.Publish(adaCtx(), "authzen", PublishRequest{BaseCommit: f.head, Message: "m",
		Files: map[string]*string{"registry.rego": new("package authzen\n\nallow if x\n")}})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "authzen/registry.rego:") || len(f.repo.commits) != 0 {
		t.Fatalf("Publish(broken) error = %v, commits %d", err, len(f.repo.commits))
	}

	none := newFixture(t)
	if _, err := none.svc.CheckDraft(adaCtx(), "authzen", draft); !errors.Is(err, ErrNoEngine) {
		t.Fatalf("CheckDraft without an engine: error = %v", err)
	}
}
