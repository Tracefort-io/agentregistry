package gitutil

import (
	"errors"
	"maps"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// writableFixture is a bare repository served over git http-backend with
// pushes enabled, seeded with two commits on main.
type writableFixture struct {
	url, dir     string
	first, tip   string
	git          func(args ...string) string
	gitInWorkdir func(args ...string) string
}

func serveWritable(t *testing.T, allowSHAWants bool) writableFixture {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is required to serve fixture repositories")
	}
	root := t.TempDir()
	bare := filepath.Join(root, "org", "policies.git")
	work := filepath.Join(t.TempDir(), "work")
	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(gitPath, append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2026-01-02T03:04:05Z", "GIT_COMMITTER_DATE=2026-01-02T03:04:05Z")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	for _, d := range []string{bare, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run(bare, "init", "--bare", "--initial-branch=main")
	run(bare, "config", "http.receivepack", "true")
	run(bare, "config", "uploadpack.allowReachableSHA1InWant", strconv.FormatBool(allowSHAWants))
	run(work, "init", "--initial-branch=main")
	run(work, "config", "user.email", "seed@example.com")
	run(work, "config", "user.name", "Seed")
	write := func(files map[string]string) {
		for rel, content := range files {
			p := filepath.Join(work, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(map[string]string{
		"README.md":                  "policies",
		"authzen/registry.rego":      "package authzen\n",
		"authzen/registry_test.rego": "package authzen_test\n",
		"authzen/data.json":          `{"a":1}`,
		"authzen/lib/util.rego":      "package authzen.lib\n",
		"other/x.rego":               "package other\n",
		"tools/run.sh":               "#!/bin/sh\n",
	})
	if err := os.Chmod(filepath.Join(work, "tools/run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(work, "add", ".")
	run(work, "commit", "-m", "seed")
	first := run(work, "rev-parse", "HEAD")
	write(map[string]string{"authzen/registry.rego": "package authzen\n\nallow := true\n"})
	run(work, "commit", "-am", "allow")
	tip := run(work, "rev-parse", "HEAD")
	run(work, "tag", "authzen/v1", first)
	run(work, "tag", "-a", "authzen/v2", "-m", "v2", tip)
	run(work, "tag", "other/v1", first)
	run(work, "push", bare, "main", "--tags")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, _ := r.BasicAuth(); user != fixtureAuth.Username() || pass != fixturePassword {
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}
		(&cgi.Handler{Path: gitPath, Args: []string{"http-backend"}, Env: []string{
			"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=" + fixtureAuth.Username(),
		}}).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return writableFixture{
		url: srv.URL + "/org/policies.git", dir: bare, first: first, tip: tip,
		git:          func(args ...string) string { return run(bare, args...) },
		gitInWorkdir: func(args ...string) string { return run(work, args...) },
	}
}

func openFixture(t *testing.T, f writableFixture) *Repo {
	t.Helper()
	repo, err := OpenRepo(f.url, fixtureAuth, Limits{MaxBytes: 1 << 20, MaxEntries: 100})
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestRepoReadFiles(t *testing.T) {
	for _, allowSHAWants := range []bool{true, false} {
		t.Run("allowSHAWants="+strconv.FormatBool(allowSHAWants), func(t *testing.T) {
			f := serveWritable(t, allowSHAWants)
			repo := openFixture(t, f)
			for _, tt := range []struct {
				name, sha, dir, wantErr string
				limits                  *Limits
				want                    map[string]string
			}{
				{name: "policy dir at tip", sha: f.tip, dir: "authzen", want: map[string]string{
					"registry.rego": "package authzen\n\nallow := true\n", "registry_test.rego": "package authzen_test\n",
					"data.json": `{"a":1}`, "lib/util.rego": "package authzen.lib\n",
				}},
				{name: "older commit", sha: f.first, dir: "authzen/lib", want: map[string]string{"util.rego": "package authzen.lib\n"}},
				{name: "missing dir is empty", sha: f.tip, dir: "nope", want: map[string]string{}},
				{name: "path escapes", sha: f.tip, dir: "../x", wantErr: "not a relative path"},
				{name: "dot git", sha: f.tip, dir: ".git/config", wantErr: "names .git"},
				{name: "not a sha", sha: "main", dir: "authzen", wantErr: "not a commit SHA"},
				{name: "entry limit", sha: f.tip, dir: "authzen", limits: &Limits{MaxEntries: 2}, wantErr: "exceeds 2 entries"},
				{name: "size limit", sha: f.tip, dir: "authzen", limits: &Limits{MaxBytes: 10}, wantErr: "exceeds the size limit"},
			} {
				r := repo
				if tt.limits != nil {
					r, _ = OpenRepo(f.url, fixtureAuth, *tt.limits)
				}
				files, err := r.ReadFiles(t.Context(), tt.sha, tt.dir)
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Errorf("%s: error = %v, want %q", tt.name, err, tt.wantErr)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", tt.name, err)
				}
				got := map[string]string{}
				for p, b := range files {
					got[p] = string(b)
				}
				if !maps.Equal(got, tt.want) {
					t.Errorf("%s: files = %v, want %v", tt.name, got, tt.want)
				}
			}
		})
	}
}

func TestRepoListTags(t *testing.T) {
	f := serveWritable(t, true)
	repo := openFixture(t, f)
	tags, err := repo.ListTags(t.Context(), "authzen/")
	if err != nil {
		t.Fatal(err)
	}
	// The annotated authzen/v2 peels to its commit.
	want := []Tag{{Name: "authzen/v1", Commit: f.first}, {Name: "authzen/v2", Commit: f.tip}}
	if len(tags) != len(want) || tags[0] != want[0] || tags[1] != want[1] {
		t.Fatalf("ListTags = %v, want %v", tags, want)
	}
	if sha, err := repo.Resolve(t.Context(), "main"); err != nil || sha != f.tip {
		t.Fatalf("Resolve(main) = %q, %v; want %q", sha, err, f.tip)
	}
}

func TestRepoCommitsAndDiff(t *testing.T) {
	f := serveWritable(t, true)
	repo := openFixture(t, f)
	infos, err := repo.Commits(t.Context(), f.first, f.tip)
	if err != nil {
		t.Fatal(err)
	}
	tip := infos[f.tip]
	if tip.SHA != f.tip || tip.Message != "allow\n" || tip.Author.Name != "Seed" || tip.Author.Email != "seed@example.com" ||
		!tip.Author.When.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("Commits[tip] = %+v", tip)
	}
	if infos[f.first].Message != "seed\n" {
		t.Fatalf("Commits[first] = %+v", infos[f.first])
	}

	changes, err := repo.Diff(t.Context(), f.first, f.tip, "authzen")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Path != "registry.rego" || string(changes[0].Old) != "package authzen\n" ||
		string(changes[0].New) != "package authzen\n\nallow := true\n" {
		t.Fatalf("Diff = %+v", changes)
	}
	if changes, err := repo.Diff(t.Context(), f.first, f.tip, "other"); err != nil || len(changes) != 0 {
		t.Fatalf("Diff(other) = %+v, %v; want none", changes, err)
	}
}

func TestRepoCommit(t *testing.T) {
	f := serveWritable(t, true)
	repo := openFixture(t, f)
	author := Signature{Name: "Ada", Email: "ada@example.com", When: time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)}
	committer := Signature{Name: "agentregistry", Email: "agentregistry@example.com", When: author.When}

	sha, err := repo.Commit(t.Context(), CommitRequest{
		Base:   f.tip,
		Branch: "policy/authzen/one",
		Files: map[string][]byte{
			"authzen/registry.rego": []byte("package authzen\n\nallow := false\n"),
			"authzen/new/rule.rego": []byte("package authzen.new\n"),
			"authzen/lib/util.rego": nil, // empties and drops authzen/lib
			"tools/run.sh":          []byte("#!/bin/sh\nexit 0\n"),
		},
		Message:   "authzen: deny by default",
		Author:    author,
		Committer: committer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.git("rev-parse", "refs/heads/policy/authzen/one"); got != sha {
		t.Fatalf("branch = %s, want %s", got, sha)
	}
	if got := f.git("rev-parse", sha+"^"); got != f.tip {
		t.Fatalf("parent = %s, want %s", got, f.tip)
	}
	if got := f.git("log", "-1", "--format=%an <%ae>|%cn|%s", sha); got != "Ada <ada@example.com>|agentregistry|authzen: deny by default" {
		t.Fatalf("commit = %q", got)
	}
	if got := f.git("show", sha+":authzen/registry.rego"); got != "package authzen\n\nallow := false" {
		t.Fatalf("registry.rego = %q", got)
	}
	if got := f.git("ls-tree", "-r", "--name-only", sha); got != strings.Join([]string{
		"README.md", "authzen/data.json", "authzen/new/rule.rego", "authzen/registry.rego",
		"authzen/registry_test.rego", "other/x.rego", "tools/run.sh",
	}, "\n") {
		t.Fatalf("tree = %q", got)
	}
	if got := f.git("ls-tree", sha, "tools/run.sh"); !strings.HasPrefix(got, "100755 ") {
		t.Fatalf("run.sh lost its executable mode: %q", got)
	}
	// git itself must accept the objects and their order.
	f.git("fsck", "--strict")

	// The branch exists now and is never moved.
	_, err = repo.Commit(t.Context(), CommitRequest{
		Base: sha, Branch: "policy/authzen/one", Files: map[string][]byte{"README.md": []byte("x")},
		Author: author, Committer: committer,
	})
	if !errors.Is(err, ErrRefExists) {
		t.Fatalf("second commit to branch: error = %v, want ErrRefExists", err)
	}
}

func TestRepoCommitOnOlderBase(t *testing.T) {
	f := serveWritable(t, true)
	repo := openFixture(t, f)
	// The base is no longer the tip of any branch, so the remote doesn't
	// advertise it; the push must still send only the new objects.
	sha, err := repo.Commit(t.Context(), CommitRequest{
		Base: f.first, Branch: "policy/other/one",
		Files:  map[string][]byte{"other/x.rego": []byte("package other\n\ndefault allow := false\n")},
		Author: Signature{Name: "Ada", Email: "ada@example.com"}, Committer: Signature{Name: "agentregistry", Email: "ar@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.git("rev-parse", sha+"^"); got != f.first {
		t.Fatalf("parent = %s, want %s", got, f.first)
	}
	f.git("fsck", "--strict")
}

func TestRepoCommitRejects(t *testing.T) {
	f := serveWritable(t, true)
	repo := openFixture(t, f)
	sig := Signature{Name: "Ada", Email: "ada@example.com"}
	for _, tt := range []struct {
		name    string
		req     CommitRequest
		wantErr error
		errText string
	}{
		{name: "no files", req: CommitRequest{Base: f.tip, Branch: "b1"}, wantErr: ErrNoChanges},
		{name: "same content", req: CommitRequest{Base: f.tip, Branch: "b2", Files: map[string][]byte{"README.md": []byte("policies")}}, wantErr: ErrNoChanges},
		{name: "delete missing", req: CommitRequest{Base: f.tip, Branch: "b3", Files: map[string][]byte{"nope.rego": nil}}, wantErr: ErrNoChanges},
		{name: "existing branch", req: CommitRequest{Base: f.tip, Branch: "main", Files: map[string][]byte{"README.md": []byte("x")}}, wantErr: ErrRefExists},
		{name: "base not sha", req: CommitRequest{Base: "main", Branch: "b4", Files: map[string][]byte{"a": []byte("x")}}, errText: "not a commit SHA"},
		{name: "bad branch", req: CommitRequest{Base: f.tip, Branch: "a..b", Files: map[string][]byte{"a": []byte("x")}}, errText: "invalid git ref name"},
		{name: "path escapes", req: CommitRequest{Base: f.tip, Branch: "b5", Files: map[string][]byte{"../a": []byte("x")}}, errText: "not a relative path"},
		{name: "absolute path", req: CommitRequest{Base: f.tip, Branch: "b6", Files: map[string][]byte{"/a": []byte("x")}}, errText: "not a relative path"},
		{name: "dot git", req: CommitRequest{Base: f.tip, Branch: "b7", Files: map[string][]byte{"x/.git/hooks/a": []byte("x")}}, errText: "names .git"},
		{name: "file as dir", req: CommitRequest{Base: f.tip, Branch: "b8", Files: map[string][]byte{"README.md/a": []byte("x")}}, errText: "is a file, not a directory"},
	} {
		tt.req.Author, tt.req.Committer = sig, sig
		_, err := repo.Commit(t.Context(), tt.req)
		switch {
		case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.wantErr)
		case tt.errText != "" && (err == nil || !strings.Contains(err.Error(), tt.errText)):
			t.Errorf("%s: error = %v, want %q", tt.name, err, tt.errText)
		}
	}
	if got := f.git("for-each-ref", "--format=%(refname)", "refs/heads/"); got != "refs/heads/main" {
		t.Fatalf("refused commits left branches: %q", got)
	}
}

func TestRepoPushTag(t *testing.T) {
	f := serveWritable(t, true)
	repo := openFixture(t, f)
	if err := repo.PushTag(t.Context(), "authzen/v3", f.tip); err != nil {
		t.Fatal(err)
	}
	if got := f.git("rev-parse", "refs/tags/authzen/v3"); got != f.tip {
		t.Fatalf("tag = %s, want %s", got, f.tip)
	}
	if err := repo.PushTag(t.Context(), "authzen/v3", f.first); !errors.Is(err, ErrRefExists) {
		t.Fatalf("moving a tag: error = %v, want ErrRefExists", err)
	}
	if got := f.git("rev-parse", "refs/tags/authzen/v3"); got != f.tip {
		t.Fatalf("tag moved to %s", got)
	}
	if err := repo.PushTag(t.Context(), "bad tag", f.tip); err == nil || !strings.Contains(err.Error(), "invalid git ref name") {
		t.Fatalf("bad tag name: error = %v", err)
	}
}

func TestRepoErrorsAreRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "authentication failed for https://x-access-token:ghp-secret@host", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	repo, err := OpenRepo(srv.URL+"/org/private.git", fixtureAuth, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	_, tagsErr := repo.ListTags(t.Context(), "")
	_, readErr := repo.ReadFiles(t.Context(), strings.Repeat("a", 40), "")
	for _, err := range []error{tagsErr, readErr} {
		if err == nil || strings.Contains(err.Error(), fixturePassword) {
			t.Fatalf("error = %v, want an error without the token", err)
		}
	}
}
