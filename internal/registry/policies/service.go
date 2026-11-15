// Package policies serves Rego policies kept in a GitHub or GitLab
// repository: it reads them live from the tracked branch, publishes edits
// as pull (merge) requests, and tags each merged change as a new version.
// OPAL tracks the same branch and loads what is merged into OPA.
//
// A policy is a top-level directory of the repository holding .rego files
// and data.json files, laid out as in an OPA bundle. Its versions
// are the tags "<policy>/v<N>".
package policies

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/githost"
	"github.com/agentregistry-dev/agentregistry/pkg/gitutil"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

var logger = logging.New("policies")

// ResourceType is the authorization resource type of a policy.
const ResourceType auth.PermissionArtifactType = "policy"

// Audit actions.
const (
	AuditActionPublish = "publish-policy"
	AuditActionTag     = "tag-policy"
)

// AuditKind is the audit resource kind of a policy.
const AuditKind = "Policy"

// maxListedVersions bounds the versions returned and checked against OPA.
const maxListedVersions = 100

var (
	// ErrNotFound is an unknown policy, version or ref.
	ErrNotFound = errors.New("not found")
	// ErrInvalid is a request the service refuses (bad name, path or content).
	ErrInvalid = errors.New("invalid request")
	// ErrConflict is a publish with nothing to change, or racing another writer.
	ErrConflict = errors.New("conflict")
)

var (
	policyName  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	packageLine = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_.\[\]"-]*)`)
	versionTag  = regexp.MustCompile(`^v([1-9][0-9]{0,8})$`)
)

// GitRepo is the repository; *gitutil.Repo implements it.
type GitRepo interface {
	Resolve(ctx context.Context, ref string) (string, error)
	ListTags(ctx context.Context, prefix string) ([]gitutil.Tag, error)
	ReadFiles(ctx context.Context, sha, dir string) (map[string][]byte, error)
	Commits(ctx context.Context, shas ...string) (map[string]gitutil.CommitInfo, error)
	Diff(ctx context.Context, from, to, dir string) ([]gitutil.FileChange, error)
	Commit(ctx context.Context, req gitutil.CommitRequest) (string, error)
	PushTag(ctx context.Context, name, sha string) error
}

// Opener connects to the repository and its host with credentials resolved
// for this call, so a rotated token takes effect at once.
type Opener func(ctx context.Context) (GitRepo, githost.Host, error)

// Authorizer decides whether the caller in ctx may act on a resource;
// auth.Authorizer implements it. Policies never reach the database, so the
// service checks here instead of a store.
type Authorizer interface {
	Check(ctx context.Context, verb auth.PermissionAction, resource auth.Resource) error
}

// LoadedModules returns the raw Rego of every module OPA has loaded.
type LoadedModules interface {
	Modules(ctx context.Context) ([]string, error)
}

// Checker refuses Rego or data that would not load into OPA. Publish runs
// it on the policy as it would be after the change.
type Checker interface {
	CheckFiles(ctx context.Context, policy string, files map[string][]byte) error
}

// Config configures the service.
type Config struct {
	Open Opener
	// Branch is the branch OPAL tracks and pull requests target.
	Branch     string
	Authorizer Authorizer
	// OPA, when set, reports which version OPA has loaded.
	OPA LoadedModules
	// Checker, when set, validates a publish before it is pushed; it
	// defaults to the Engine's check.
	Checker Checker
	// Engine, when set, serves the editor's format, check, evaluate and test.
	Engine Engine
	// Committer signs the commits the registry pushes; the caller is
	// the author.
	Committer gitutil.Signature
	Audit     audit.Recorder
	Now       func() time.Time
}

// Service reads and publishes policies.
type Service struct {
	cfg Config
}

// New returns a Service.
func New(cfg Config) (*Service, error) {
	if cfg.Open == nil || cfg.Authorizer == nil {
		return nil, errors.New("policies: Open and Authorizer are required")
	}
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Service{cfg: cfg}
	if s.cfg.Checker == nil && s.cfg.Engine != nil {
		s.cfg.Checker = CheckerFunc(s.checkFiles)
	}
	return s, nil
}

// CheckerFunc adapts a function to Checker.
type CheckerFunc func(ctx context.Context, policy string, files map[string][]byte) error

// CheckFiles implements Checker.
func (f CheckerFunc) CheckFiles(ctx context.Context, policy string, files map[string][]byte) error {
	return f(ctx, policy, files)
}

// PolicySummary is one policy in a listing.
type PolicySummary struct {
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
	// DataPaths are the data documents the policy's data files load into.
	DataPaths []string `json:"dataPaths"`
	Files     int      `json:"files"`
	// LatestVersion is the newest version tag ("v3"), empty before the first merge.
	LatestVersion string `json:"latestVersion,omitempty"`
}

// PolicyFile is one file of a policy, with its path relative to the policy.
type PolicyFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Policy is a policy's files at one commit.
type Policy struct {
	PolicySummary
	// Commit is the commit the files were read at; publish edits on top of it.
	Commit string `json:"commit"`
	// Ref is what was asked for: the branch, a version or a commit.
	Ref   string       `json:"ref"`
	Files []PolicyFile `json:"files"`
}

// PolicyVersion is one merged change of a policy.
type PolicyVersion struct {
	Version string    `json:"version"`
	Tag     string    `json:"tag"`
	Commit  string    `json:"commit"`
	Author  string    `json:"author"`
	Date    time.Time `json:"date"`
	Message string    `json:"message"`
}

// PolicyChange is one file that differs between two refs.
type PolicyChange struct {
	Path string  `json:"path"`
	Old  *string `json:"old,omitempty"`
	New  *string `json:"new,omitempty"`
}

// List returns the policies on the branch the caller may read.
func (s *Service) List(ctx context.Context) ([]PolicySummary, error) {
	repo, _, err := s.cfg.Open(ctx)
	if err != nil {
		return nil, err
	}
	head, err := repo.Resolve(ctx, s.cfg.Branch)
	if err != nil {
		return nil, fmt.Errorf("resolve branch %s: %w", s.cfg.Branch, err)
	}
	files, err := repo.ReadFiles(ctx, head, "")
	if err != nil {
		return nil, err
	}
	byPolicy := map[string]map[string][]byte{}
	for p, content := range files {
		dir, rel, ok := strings.Cut(p, "/")
		if !ok || !policyName.MatchString(dir) {
			continue
		}
		if byPolicy[dir] == nil {
			byPolicy[dir] = map[string][]byte{}
		}
		byPolicy[dir][rel] = content
	}
	tags, err := repo.ListTags(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]PolicySummary, 0, len(byPolicy))
	for name, pf := range byPolicy {
		if !hasRego(pf) {
			continue
		}
		// Each policy is checked on its own; a caller sees only those it may read.
		if err := s.cfg.Authorizer.Check(ctx, auth.PermissionActionRead, resource(name)); err != nil {
			if errors.Is(err, auth.ErrForbidden) {
				continue
			}
			return nil, err
		}
		sum := summarize(name, pf)
		if v := latestVersion(name, tags); v != nil {
			sum.LatestVersion = "v" + strconv.Itoa(v.n)
		}
		out = append(out, sum)
	}
	slices.SortFunc(out, func(a, b PolicySummary) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Get returns a policy's files at ref: "" for the branch head, a version
// ("v3"), or a commit SHA.
func (s *Service) Get(ctx context.Context, name, ref string) (Policy, error) {
	if err := s.authorize(ctx, auth.PermissionActionRead, name); err != nil {
		return Policy{}, err
	}
	repo, _, err := s.cfg.Open(ctx)
	if err != nil {
		return Policy{}, err
	}
	sha, err := s.resolve(ctx, repo, name, ref)
	if err != nil {
		return Policy{}, err
	}
	files, err := repo.ReadFiles(ctx, sha, name)
	if err != nil {
		return Policy{}, err
	}
	if ref != "" && len(files) == 0 {
		return Policy{}, fmt.Errorf("%w: policy %q at %s", ErrNotFound, name, ref)
	}
	tags, err := repo.ListTags(ctx, name+"/v")
	if err != nil {
		return Policy{}, err
	}
	p := Policy{PolicySummary: summarize(name, files), Commit: sha, Ref: cmp.Or(ref, s.cfg.Branch), Files: make([]PolicyFile, 0, len(files))}
	if v := latestVersion(name, tags); v != nil {
		p.LatestVersion = "v" + strconv.Itoa(v.n)
	}
	for _, rel := range sortedKeys(files) {
		p.Files = append(p.Files, PolicyFile{Path: rel, Content: string(files[rel])})
	}
	return p, nil
}

// Versions returns a policy's versions, newest first.
func (s *Service) Versions(ctx context.Context, name string) ([]PolicyVersion, error) {
	if err := s.authorize(ctx, auth.PermissionActionRead, name); err != nil {
		return nil, err
	}
	repo, _, err := s.cfg.Open(ctx)
	if err != nil {
		return nil, err
	}
	tags, err := repo.ListTags(ctx, name+"/v")
	if err != nil {
		return nil, err
	}
	versions := versionTags(name, tags)
	if len(versions) > maxListedVersions {
		versions = versions[:maxListedVersions]
	}
	shas := make([]string, 0, len(versions))
	for _, v := range versions {
		shas = append(shas, v.tag.Commit)
	}
	infos, err := repo.Commits(ctx, shas...)
	if err != nil {
		return nil, err
	}
	out := make([]PolicyVersion, 0, len(versions))
	for _, v := range versions {
		info := infos[v.tag.Commit]
		out = append(out, PolicyVersion{
			Version: "v" + strconv.Itoa(v.n), Tag: v.tag.Name, Commit: v.tag.Commit,
			Author: info.Author.Name, Date: info.Committer.When, Message: strings.TrimSpace(info.Message),
		})
	}
	return out, nil
}

// Diff returns the files of a policy that differ between two refs (see Get).
func (s *Service) Diff(ctx context.Context, name, from, to string) ([]PolicyChange, error) {
	if err := s.authorize(ctx, auth.PermissionActionRead, name); err != nil {
		return nil, err
	}
	repo, _, err := s.cfg.Open(ctx)
	if err != nil {
		return nil, err
	}
	fromSHA, err := s.resolve(ctx, repo, name, from)
	if err != nil {
		return nil, err
	}
	toSHA, err := s.resolve(ctx, repo, name, to)
	if err != nil {
		return nil, err
	}
	changes, err := repo.Diff(ctx, fromSHA, toSHA, name)
	if err != nil {
		return nil, err
	}
	out := make([]PolicyChange, 0, len(changes))
	for _, c := range changes {
		out = append(out, PolicyChange{Path: c.Path, Old: textOrNil(c.Old), New: textOrNil(c.New)})
	}
	return out, nil
}

// Pending returns the open pull requests into the branch that touch the policy.
func (s *Service) Pending(ctx context.Context, name string) ([]githost.PullRequest, error) {
	if err := s.authorize(ctx, auth.PermissionActionRead, name); err != nil {
		return nil, err
	}
	_, host, err := s.cfg.Open(ctx)
	if err != nil {
		return nil, err
	}
	pulls, err := host.ListOpenPullRequests(ctx, s.cfg.Branch)
	if err != nil {
		return nil, err
	}
	out := []githost.PullRequest{}
	for _, pr := range pulls {
		files, err := host.ChangedFiles(ctx, pr.Number)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(files, func(f string) bool { return strings.HasPrefix(f, name+"/") }) {
			out = append(out, pr)
		}
	}
	return out, nil
}

// resolve turns a ref into a commit: "" is the branch head, "v<N>" the
// policy's version tag, anything else a commit SHA, branch or tag.
func (s *Service) resolve(ctx context.Context, repo GitRepo, name, ref string) (string, error) {
	target := ref
	switch {
	case ref == "":
		target = s.cfg.Branch
	case versionTag.MatchString(ref):
		target = "refs/tags/" + name + "/" + ref
	}
	sha, err := repo.Resolve(ctx, target)
	if errors.Is(err, gitutil.ErrRefNotFound) {
		return "", fmt.Errorf("%w: %s", ErrNotFound, cmp.Or(ref, s.cfg.Branch))
	}
	return sha, err
}

func (s *Service) authorize(ctx context.Context, verb auth.PermissionAction, name string) error {
	if !policyName.MatchString(name) {
		return fmt.Errorf("%w: policy name %q must be lowercase letters, digits, '-' or '_'", ErrInvalid, name)
	}
	return s.cfg.Authorizer.Check(ctx, verb, resource(name))
}

func resource(name string) auth.Resource {
	return auth.Resource{Type: ResourceType, Name: name}
}

func summarize(name string, files map[string][]byte) PolicySummary {
	sum := PolicySummary{Name: name, Files: len(files), Packages: []string{}, DataPaths: []string{}}
	for _, rel := range sortedKeys(files) {
		switch {
		case strings.HasSuffix(rel, ".rego"):
			if m := packageLine.FindSubmatch(files[rel]); m != nil {
				pkg := string(m[1])
				if !slices.Contains(sum.Packages, pkg) {
					sum.Packages = append(sum.Packages, pkg)
				}
			}
		case isDataFile(rel):
			sum.DataPaths = append(sum.DataPaths, dataPath(name, rel))
		}
	}
	return sum
}

// dataPath is where an OPA bundle loads a data file: its directory, from
// the repository root.
func dataPath(name, rel string) string {
	dir := path.Dir(path.Join(name, rel))
	return "data." + strings.ReplaceAll(dir, "/", ".")
}

func isDataFile(rel string) bool {
	base := path.Base(rel)
	return base == "data.json"
}

func hasRego(files map[string][]byte) bool {
	for rel := range files {
		if strings.HasSuffix(rel, ".rego") {
			return true
		}
	}
	return false
}

type versionedTag struct {
	n   int
	tag gitutil.Tag
}

// versionTags returns the policy's "<name>/v<N>" tags, newest first.
func versionTags(name string, tags []gitutil.Tag) []versionedTag {
	var out []versionedTag
	for _, t := range tags {
		rest, ok := strings.CutPrefix(t.Name, name+"/")
		if !ok {
			continue
		}
		if m := versionTag.FindStringSubmatch(rest); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, versionedTag{n: n, tag: t})
		}
	}
	slices.SortFunc(out, func(a, b versionedTag) int { return b.n - a.n })
	return out
}

func latestVersion(name string, tags []gitutil.Tag) *versionedTag {
	if v := versionTags(name, tags); len(v) > 0 {
		return &v[0]
	}
	return nil
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func textOrNil(b []byte) *string {
	if b == nil {
		return nil
	}
	s := string(b)
	return &s
}

// TokenFrom returns the API token in git credentials: the password, or the
// username of a token-only userinfo.
func TokenFrom(u *url.Userinfo) string {
	if u == nil {
		return ""
	}
	if p, ok := u.Password(); ok {
		return p
	}
	return u.Username()
}
