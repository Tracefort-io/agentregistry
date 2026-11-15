package gitutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
)

var (
	// ErrRefExists is a push that would move an existing branch or tag.
	ErrRefExists = errors.New("git ref already exists")
	// ErrNoChanges is a commit that would not change the base tree.
	ErrNoChanges = errors.New("no changes to commit")
)

// Repo reads and writes one repository over git's smart HTTP protocol,
// holding nothing on disk: every call fetches what it needs into memory.
type Repo struct {
	cloneURL string
	auth     *url.Userinfo
	limits   Limits
}

// Tag is a remote tag and the commit it names.
type Tag struct {
	Name   string
	Commit string
}

// Signature is a commit's author or committer.
type Signature struct {
	Name  string
	Email string
	When  time.Time
}

// CommitInfo describes one commit.
type CommitInfo struct {
	SHA       string
	Message   string
	Author    Signature
	Committer Signature
}

// FileChange is one path that differs between two commits; Old is nil for
// an added file and New is nil for a deleted one.
type FileChange struct {
	Path string
	Old  []byte
	New  []byte
}

// CommitRequest is one commit on top of Base, pushed as a new Branch.
type CommitRequest struct {
	Base   string
	Branch string
	// Files maps repository paths to their new contents; a nil value
	// deletes the path.
	Files     map[string][]byte
	Message   string
	Author    Signature
	Committer Signature
}

// OpenRepo returns a Repo for rawURL, a GitHub/GitLab web URL or any .git
// clone URL; nil auth is anonymous. limits caps what one read loads.
func OpenRepo(rawURL string, auth *url.Userinfo, limits Limits) (*Repo, error) {
	cloneURL, _, _, err := ParseGitURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse Git URL: %w", err)
	}
	return &Repo{cloneURL: cloneURL, auth: auth, limits: limits}, nil
}

// Resolve resolves ref (a SHA, branch, tag, refs/ name, or "" for HEAD) to
// a commit SHA.
func (r *Repo) Resolve(ctx context.Context, ref string) (string, error) {
	return resolveRef(ctx, r.cloneURL, ref, r.auth)
}

// ListTags returns the remote tags whose names start with prefix, peeled
// to their commits, sorted by name.
func (r *Repo) ListTags(ctx context.Context, prefix string) ([]Tag, error) {
	refs, err := r.listRefs(ctx)
	if err != nil {
		return nil, err
	}
	byName := map[string]string{}
	for _, ref := range refs {
		name, ok := strings.CutPrefix(ref.Name().String(), "refs/tags/")
		if !ok || ref.Type() != plumbing.HashReference {
			continue
		}
		// The peeled entry ("<tag>^{}") names an annotated tag's commit.
		name, peeled := strings.CutSuffix(name, "^{}")
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if _, seen := byName[name]; !seen || peeled {
			byName[name] = ref.Hash().String()
		}
	}
	tags := make([]Tag, 0, len(byName))
	for name, sha := range byName {
		tags = append(tags, Tag{Name: name, Commit: sha})
	}
	slices.SortFunc(tags, func(a, b Tag) int { return strings.Compare(a.Name, b.Name) })
	return tags, nil
}

// ReadFiles returns the regular files under dir ("" for the whole tree) at
// commit sha, keyed by their paths relative to dir. Symlinks and
// submodules are skipped.
func (r *Repo) ReadFiles(ctx context.Context, sha, dir string) (map[string][]byte, error) {
	repo, err := r.fetch(ctx, sha)
	if err != nil {
		return nil, err
	}
	return r.readTree(repo, sha, dir)
}

// Commits returns the details of each commit in shas, fetched together.
func (r *Repo) Commits(ctx context.Context, shas ...string) (map[string]CommitInfo, error) {
	if len(shas) == 0 {
		return map[string]CommitInfo{}, nil
	}
	repo, err := r.fetch(ctx, shas...)
	if err != nil {
		return nil, err
	}
	out := make(map[string]CommitInfo, len(shas))
	for _, sha := range shas {
		c, err := repo.CommitObject(plumbing.NewHash(sha))
		if err != nil {
			return nil, fmt.Errorf("read commit %s: %w", sha, err)
		}
		out[sha] = commitInfo(c)
	}
	return out, nil
}

// Diff returns the files under dir that differ between commits from and
// to, sorted by path.
func (r *Repo) Diff(ctx context.Context, from, to, dir string) ([]FileChange, error) {
	repo, err := r.fetch(ctx, from, to)
	if err != nil {
		return nil, err
	}
	before, err := r.readTree(repo, from, dir)
	if err != nil {
		return nil, err
	}
	after, err := r.readTree(repo, to, dir)
	if err != nil {
		return nil, err
	}
	var changes []FileChange
	for p, old := range before {
		if updated, ok := after[p]; !ok || !bytes.Equal(old, updated) {
			changes = append(changes, FileChange{Path: p, Old: old, New: after[p]})
		}
	}
	for p, added := range after {
		if _, ok := before[p]; !ok {
			changes = append(changes, FileChange{Path: p, New: added})
		}
	}
	slices.SortFunc(changes, func(a, b FileChange) int { return strings.Compare(a.Path, b.Path) })
	return changes, nil
}

// Commit writes req.Files on top of req.Base as one commit and pushes it as
// the new branch req.Branch, returning the commit's SHA. An existing branch
// is never moved (ErrRefExists).
func (r *Repo) Commit(ctx context.Context, req CommitRequest) (string, error) {
	if !plumbing.IsHash(req.Base) {
		return "", fmt.Errorf("commit base %q is not a commit SHA", req.Base)
	}
	if err := checkRefName("refs/heads/" + req.Branch); err != nil {
		return "", err
	}
	if len(req.Files) == 0 {
		return "", ErrNoChanges
	}
	changes := make(map[string][]byte, len(req.Files))
	for p, content := range req.Files {
		clean, err := cleanRepoPath(p)
		if err != nil {
			return "", err
		}
		changes[clean] = content
	}

	repo, err := r.fetch(ctx, req.Base)
	if err != nil {
		return "", err
	}
	base, err := repo.CommitObject(plumbing.NewHash(req.Base))
	if err != nil {
		return "", fmt.Errorf("read commit %s: %w", req.Base, err)
	}
	baseTree, err := base.Tree()
	if err != nil {
		return "", err
	}
	treeHash, err := buildTree(repo.Storer, baseTree, changes)
	if err != nil {
		return "", err
	}
	if treeHash == baseTree.Hash {
		return "", ErrNoChanges
	}
	commit := &object.Commit{
		Author:       signature(req.Author),
		Committer:    signature(req.Committer),
		Message:      req.Message,
		TreeHash:     treeHash,
		ParentHashes: []plumbing.Hash{base.Hash},
	}
	commitHash, err := storeObject(repo.Storer, commit)
	if err != nil {
		return "", err
	}
	if err := r.push(ctx, repo, "refs/heads/"+req.Branch, commitHash); err != nil {
		return "", err
	}
	return commitHash.String(), nil
}

// PushTag creates the lightweight tag name on commit sha. An existing tag is
// never moved (ErrRefExists).
func (r *Repo) PushTag(ctx context.Context, name, sha string) error {
	if !plumbing.IsHash(sha) {
		return fmt.Errorf("tag target %q is not a commit SHA", sha)
	}
	ref := "refs/tags/" + name
	if err := checkRefName(ref); err != nil {
		return err
	}
	repo, err := r.fetch(ctx, sha)
	if err != nil {
		return err
	}
	return r.push(ctx, repo, ref, plumbing.NewHash(sha))
}

func (r *Repo) listRefs(ctx context.Context) ([]*plumbing.Reference, error) {
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: git.DefaultRemoteName, URLs: []string{r.cloneURL}})
	refs, err := remote.ListContext(ctx, &git.ListOptions{Auth: basicAuth(r.auth), PeelingOption: git.AppendPeeled})
	if err != nil && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil, redact(fmt.Errorf("list refs of %s: %w", r.cloneURL, err), r.auth)
	}
	return refs, nil
}

// fetch shallow-fetches shas into a new in-memory repository.
func (r *Repo) fetch(ctx context.Context, shas ...string) (*git.Repository, error) {
	repo, err := git.Init(memory.NewStorage(), nil)
	if err != nil {
		return nil, err
	}
	if err := fetchCommits(ctx, repo, r.cloneURL, r.auth, shas...); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *Repo) readTree(repo *git.Repository, sha, dir string) (map[string][]byte, error) {
	commit, err := repo.CommitObject(plumbing.NewHash(sha))
	if err != nil {
		return nil, fmt.Errorf("read commit %s: %w", sha, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	if dir != "" {
		clean, err := cleanRepoPath(dir)
		if err != nil {
			return nil, err
		}
		if tree, err = tree.Tree(clean); errors.Is(err, object.ErrDirectoryNotFound) {
			return map[string][]byte{}, nil
		} else if err != nil {
			return nil, fmt.Errorf("read %q at %s: %w", dir, sha, err)
		}
	}
	files := map[string][]byte{}
	var size int64
	err = tree.Files().ForEach(func(f *object.File) error {
		if f.Mode != filemode.Regular && f.Mode != filemode.Executable && f.Mode != filemode.Deprecated {
			return nil
		}
		size += f.Size
		if r.limits.MaxEntries > 0 && len(files) >= r.limits.MaxEntries {
			return fmt.Errorf("git source exceeds %d entries", r.limits.MaxEntries)
		}
		if r.limits.MaxBytes > 0 && size > r.limits.MaxBytes {
			return fmt.Errorf("git source exceeds the size limit of %d bytes", r.limits.MaxBytes)
		}
		contents, err := f.Contents()
		if err != nil {
			return err
		}
		files[f.Name] = []byte(contents)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// push creates ref on the remote at hash; an existing ref is never moved.
// The objects sent are those reachable from hash that the remote lacks; the
// shallow fetch boundary counts as present, so only new objects are sent.
func (r *Repo) push(ctx context.Context, repo *git.Repository, ref string, hash plumbing.Hash) error {
	refs, err := r.listRefs(ctx)
	if err != nil {
		return err
	}
	for _, existing := range refs {
		if existing.Name().String() == ref {
			return fmt.Errorf("%w: %s", ErrRefExists, ref)
		}
	}
	if err := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(ref), hash)); err != nil {
		return err
	}
	remote := git.NewRemote(repo.Storer, &config.RemoteConfig{Name: git.DefaultRemoteName, URLs: []string{r.cloneURL}})
	err = remote.PushContext(ctx, &git.PushOptions{
		RemoteName: git.DefaultRemoteName,
		RefSpecs:   []config.RefSpec{config.RefSpec(ref + ":" + ref)},
		Auth:       basicAuth(r.auth),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, git.NoErrAlreadyUpToDate), isRefExists(err):
		// Another writer created the ref between the check and the push.
		return fmt.Errorf("%w: %s", ErrRefExists, ref)
	default:
		return redact(fmt.Errorf("push %s to %s: %w", ref, r.cloneURL, err), r.auth)
	}
}

// isRefExists reports a server refusing to update an existing ref.
func isRefExists(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "non-fast-forward")
}

// fetchCommits shallow-fetches shas into repo by hash, which the server must
// allow (GitHub and GitLab do); otherwise it fetches the advertised refs.
func fetchCommits(ctx context.Context, repo *git.Repository, cloneURL string, auth *url.Userinfo, shas ...string) error {
	specs := make([]config.RefSpec, 0, len(shas))
	seen := map[string]bool{}
	for _, sha := range shas {
		if !plumbing.IsHash(sha) {
			return fmt.Errorf("%q is not a commit SHA", sha)
		}
		sha = strings.ToLower(sha)
		if seen[sha] {
			continue
		}
		seen[sha] = true
		specs = append(specs, config.RefSpec(fmt.Sprintf("%s:refs/fetched/%d", sha, len(specs))))
	}
	remote := git.NewRemote(repo.Storer, &config.RemoteConfig{Name: git.DefaultRemoteName, URLs: []string{cloneURL}})
	opts := &git.FetchOptions{RefSpecs: specs, Depth: 1, Tags: git.NoTags, Auth: basicAuth(auth)}
	err := remote.FetchContext(ctx, opts)
	if errors.Is(err, git.ErrExactSHA1NotSupported) {
		// Servers without allow-reachable-sha1-in-want only serve advertised refs, so fetch their history.
		opts.RefSpecs = []config.RefSpec{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}
		opts.Depth = 0
		err = remote.FetchContext(ctx, opts)
	}
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return redact(fmt.Errorf("fetch %s from %s: %w", strings.Join(shas, ","), cloneURL, err), auth)
	}
	return nil
}

// buildTree stores tree with changes applied (paths relative to tree; nil
// content deletes) and returns the new tree's hash. Directories left empty
// are dropped, as git cannot store them.
func buildTree(s storer.EncodedObjectStorer, tree *object.Tree, changes map[string][]byte) (plumbing.Hash, error) {
	entries := map[string]object.TreeEntry{}
	if tree != nil {
		for _, e := range tree.Entries {
			entries[e.Name] = e
		}
	}
	// Group the changes by their first path element.
	files := map[string][]byte{}
	subdirs := map[string]map[string][]byte{}
	for p, content := range changes {
		head, rest, nested := strings.Cut(p, "/")
		if !nested {
			files[head] = content
			continue
		}
		if subdirs[head] == nil {
			subdirs[head] = map[string][]byte{}
		}
		subdirs[head][rest] = content
	}
	for name, content := range files {
		if content == nil {
			delete(entries, name)
			continue
		}
		blob := s.NewEncodedObject()
		blob.SetType(plumbing.BlobObject)
		w, err := blob.Writer()
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if _, err := w.Write(content); err != nil {
			return plumbing.ZeroHash, err
		}
		if err := w.Close(); err != nil {
			return plumbing.ZeroHash, err
		}
		hash, err := s.SetEncodedObject(blob)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		mode := filemode.Regular
		if e, ok := entries[name]; ok && e.Mode == filemode.Executable {
			mode = filemode.Executable
		}
		entries[name] = object.TreeEntry{Name: name, Mode: mode, Hash: hash}
	}
	for name, sub := range subdirs {
		var child *object.Tree
		if e, ok := entries[name]; ok {
			if e.Mode != filemode.Dir {
				return plumbing.ZeroHash, fmt.Errorf("%q is a file, not a directory", name)
			}
			t, err := object.GetTree(s, e.Hash)
			if err != nil {
				return plumbing.ZeroHash, err
			}
			child = t
		}
		hash, err := buildTree(s, child, sub)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		empty, err := isEmptyTree(s, hash)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if empty {
			delete(entries, name)
			continue
		}
		entries[name] = object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: hash}
	}
	out := &object.Tree{Entries: make([]object.TreeEntry, 0, len(entries))}
	for _, e := range entries {
		out.Entries = append(out.Entries, e)
	}
	// Git orders tree entries by name, with directories compared as "name/".
	slices.SortFunc(out.Entries, func(a, b object.TreeEntry) int {
		return strings.Compare(treeSortKey(a), treeSortKey(b))
	})
	return storeObject(s, out)
}

func treeSortKey(e object.TreeEntry) string {
	if e.Mode == filemode.Dir {
		return e.Name + "/"
	}
	return e.Name
}

func isEmptyTree(s storer.EncodedObjectStorer, h plumbing.Hash) (bool, error) {
	t, err := object.GetTree(s, h)
	if err != nil {
		return false, err
	}
	return len(t.Entries) == 0, nil
}

type encoder interface {
	Encode(plumbing.EncodedObject) error
}

func storeObject(s storer.EncodedObjectStorer, o encoder) (plumbing.Hash, error) {
	obj := s.NewEncodedObject()
	if err := o.Encode(obj); err != nil {
		return plumbing.ZeroHash, err
	}
	return s.SetEncodedObject(obj)
}

func signature(s Signature) object.Signature {
	when := s.When
	if when.IsZero() {
		when = time.Now()
	}
	return object.Signature{Name: s.Name, Email: s.Email, When: when}
}

func commitInfo(c *object.Commit) CommitInfo {
	return CommitInfo{
		SHA:       c.Hash.String(),
		Message:   c.Message,
		Author:    Signature{Name: c.Author.Name, Email: c.Author.Email, When: c.Author.When},
		Committer: Signature{Name: c.Committer.Name, Email: c.Committer.Email, When: c.Committer.When},
	}
}

// cleanRepoPath accepts a relative, slash-separated path inside the
// repository and returns it cleaned.
func cleanRepoPath(p string) (string, error) {
	clean := path.Clean(p)
	if p == "" || clean == "." || path.IsAbs(p) || clean == ".." || strings.HasPrefix(clean, "../") ||
		strings.Contains(p, "\\") || strings.Contains(p, "\x00") {
		return "", fmt.Errorf("path %q is not a relative path inside the repository", p)
	}
	if slices.Contains(strings.Split(clean, "/"), ".git") {
		return "", fmt.Errorf("path %q names .git", p)
	}
	return clean, nil
}

func checkRefName(ref string) error {
	name := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/tags/")
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, " ~^:?*[\\\x7f") ||
		strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".lock") ||
		strings.HasSuffix(name, ".") || strings.Contains(name, "//") || strings.Contains(name, "@{") {
		return fmt.Errorf("invalid git ref name %q", ref)
	}
	for _, r := range name {
		if r < 0x20 {
			return fmt.Errorf("invalid git ref name %q", ref)
		}
	}
	return nil
}
