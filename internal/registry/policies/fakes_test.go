package policies

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/githost"
	"github.com/agentregistry-dev/agentregistry/pkg/gitutil"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

// fakeRepo is an in-memory GitRepo: each commit is a full tree.
type fakeRepo struct {
	mu      sync.Mutex
	trees   map[string]map[string][]byte
	infos   map[string]gitutil.CommitInfo
	refs    map[string]string
	commits []gitutil.CommitRequest
	// tagRace, when set, creates the named tag just before the first push of it.
	tagRace map[string]string
	n       int
}

func sha(n int) string { return fmt.Sprintf("%040x", n) }

func newFakeRepo() *fakeRepo {
	return &fakeRepo{trees: map[string]map[string][]byte{}, infos: map[string]gitutil.CommitInfo{}, refs: map[string]string{}}
}

// add records a commit holding files and returns its SHA.
func (r *fakeRepo) add(files map[string]string, msg string) string {
	r.n++
	s := sha(r.n)
	tree := map[string][]byte{}
	for p, c := range files {
		tree[p] = []byte(c)
	}
	r.trees[s] = tree
	r.infos[s] = gitutil.CommitInfo{SHA: s, Message: msg + "\n", Author: gitutil.Signature{Name: "Seed"},
		Committer: gitutil.Signature{When: time.Date(2026, 1, r.n, 0, 0, 0, 0, time.UTC)}}
	return s
}

func (r *fakeRepo) Resolve(_ context.Context, ref string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.trees[ref]; ok {
		return ref, nil
	}
	for _, name := range []string{ref, "refs/tags/" + ref, "refs/heads/" + ref} {
		if s, ok := r.refs[name]; ok {
			return s, nil
		}
	}
	return "", fmt.Errorf("%w: %q", gitutil.ErrRefNotFound, ref)
}

func (r *fakeRepo) ListTags(_ context.Context, prefix string) ([]gitutil.Tag, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var tags []gitutil.Tag
	for name, s := range r.refs {
		if t, ok := strings.CutPrefix(name, "refs/tags/"); ok && strings.HasPrefix(t, prefix) {
			tags = append(tags, gitutil.Tag{Name: t, Commit: s})
		}
	}
	slices.SortFunc(tags, func(a, b gitutil.Tag) int { return strings.Compare(a.Name, b.Name) })
	return tags, nil
}

func (r *fakeRepo) ReadFiles(_ context.Context, s, dir string) (map[string][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tree, ok := r.trees[s]
	if !ok {
		return nil, fmt.Errorf("no commit %s", s)
	}
	out := map[string][]byte{}
	for p, c := range tree {
		if dir == "" {
			out[p] = c
		} else if rel, ok := strings.CutPrefix(p, dir+"/"); ok {
			out[rel] = c
		}
	}
	return out, nil
}

func (r *fakeRepo) Commits(_ context.Context, shas ...string) (map[string]gitutil.CommitInfo, error) {
	out := map[string]gitutil.CommitInfo{}
	for _, s := range shas {
		out[s] = r.infos[s]
	}
	return out, nil
}

func (r *fakeRepo) Diff(ctx context.Context, from, to, dir string) ([]gitutil.FileChange, error) {
	before, err := r.ReadFiles(ctx, from, dir)
	if err != nil {
		return nil, err
	}
	after, err := r.ReadFiles(ctx, to, dir)
	if err != nil {
		return nil, err
	}
	var out []gitutil.FileChange
	for _, p := range slices.Sorted(maps.Keys(mergeKeys(before, after))) {
		if string(before[p]) != string(after[p]) || (before[p] == nil) != (after[p] == nil) {
			out = append(out, gitutil.FileChange{Path: p, Old: before[p], New: after[p]})
		}
	}
	return out, nil
}

func mergeKeys(a, b map[string][]byte) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func (r *fakeRepo) Commit(_ context.Context, req gitutil.CommitRequest) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.refs["refs/heads/"+req.Branch]; ok {
		return "", gitutil.ErrRefExists
	}
	base, ok := r.trees[req.Base]
	if !ok {
		return "", fmt.Errorf("no commit %s", req.Base)
	}
	tree := maps.Clone(base)
	changed := false
	for p, c := range req.Files {
		old, had := tree[p]
		switch {
		case c == nil && had:
			delete(tree, p)
			changed = true
		case c != nil && (!had || string(old) != string(c)):
			tree[p] = c
			changed = true
		}
	}
	if !changed {
		return "", gitutil.ErrNoChanges
	}
	r.n++
	s := sha(r.n)
	r.trees[s] = tree
	r.refs["refs/heads/"+req.Branch] = s
	r.commits = append(r.commits, req)
	return s, nil
}

func (r *fakeRepo) PushTag(_ context.Context, name, s string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if other, ok := r.tagRace[name]; ok {
		delete(r.tagRace, name)
		r.refs["refs/tags/"+name] = other
	}
	if _, ok := r.refs["refs/tags/"+name]; ok {
		return gitutil.ErrRefExists
	}
	r.refs["refs/tags/"+name] = s
	return nil
}

// fakeHost is an in-memory githost.Host.
type fakeHost struct {
	opened  []githost.NewPullRequest
	open    []githost.PullRequest
	files   map[int][]string
	openErr error
}

func (h *fakeHost) OpenPullRequest(_ context.Context, pr githost.NewPullRequest) (githost.PullRequest, error) {
	if h.openErr != nil {
		return githost.PullRequest{}, h.openErr
	}
	h.opened = append(h.opened, pr)
	return githost.PullRequest{Number: 40 + len(h.opened), Title: pr.Title, URL: fmt.Sprintf("https://git/pr/%d", 40+len(h.opened)),
		HeadBranch: pr.Head, BaseBranch: pr.Base}, nil
}

func (h *fakeHost) ListOpenPullRequests(context.Context, string) ([]githost.PullRequest, error) {
	return h.open, nil
}

func (h *fakeHost) ChangedFiles(_ context.Context, n int) ([]string, error) {
	return h.files[n], nil
}

const webhookSecret = "s3cret"

func (h *fakeHost) ParseWebhook(header http.Header, body []byte) (githost.MergeEvent, bool, error) {
	if header.Get("X-Test-Secret") != webhookSecret {
		return githost.MergeEvent{}, false, githost.ErrBadSignature
	}
	var n int
	var base, commit string
	if _, err := fmt.Sscanf(string(body), "merged %d %s %s", &n, &base, &commit); err != nil {
		return githost.MergeEvent{}, false, nil
	}
	return githost.MergeEvent{Number: n, BaseBranch: base, MergeCommit: commit}, true, nil
}

// fakeAuthz allows (verb, policy) pairs listed in allow.
type fakeAuthz struct {
	allow map[string]bool
	calls []string
}

func (a *fakeAuthz) Check(_ context.Context, verb auth.PermissionAction, r auth.Resource) error {
	key := string(verb) + " " + string(r.Type) + "/" + r.Name
	a.calls = append(a.calls, key)
	if a.allow == nil || a.allow[key] || a.allow[string(verb)+" "+string(r.Type)+"/*"] {
		return nil
	}
	return fmt.Errorf("%w: %s", auth.ErrForbidden, key)
}

type fakeChecker struct {
	got map[string][]byte
	err error
}

func (c *fakeChecker) CheckFiles(_ context.Context, _ string, files map[string][]byte) error {
	c.got = files
	return c.err
}

type fakeOPA struct{ modules []string }

func (o fakeOPA) Modules(context.Context) ([]string, error) { return o.modules, nil }

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Record(_ context.Context, e audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

type session struct{ p auth.Principal }

func (s session) Principal() auth.Principal { return s.p }

var ada = auth.Principal{
	Subject: "u-ada", Issuer: "https://idp.acme.io/realms/acme", Username: "ada",
	Claims: map[string]any{"email": "ada@acme.io"},
}

func adaCtx() context.Context { return auth.AuthSessionTo(context.Background(), session{ada}) }

var errBoom = errors.New("boom")
