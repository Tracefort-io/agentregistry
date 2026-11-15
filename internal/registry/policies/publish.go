package policies

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/githost"
	"github.com/agentregistry-dev/agentregistry/pkg/gitutil"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

const (
	maxPublishFiles = 200
	// The server's HTTP_MAX_BODY_BYTES (1 MiB by default) caps a publish first.
	maxFileBytes      = 512 << 10
	maxPublishBytes   = 1 << 20
	maxMessageBytes   = 8 << 10
	maxWebhookBody    = 4 << 20
	webhookTimeout    = time.Minute
	maxTagAttempts    = 3
	publishBranchRoot = "policy"
)

// PublishRequest is an edit of one policy on top of BaseCommit.
type PublishRequest struct {
	// BaseCommit is the commit the edit started from (Policy.Commit).
	BaseCommit string
	// Files maps paths relative to the policy to their new contents; nil
	// deletes the file. Only .rego files and data.json are allowed.
	Files map[string]*string
	// Message is the commit message; its first line titles the pull request.
	Message string
}

// PolicyPublishResult is the pull request that carries the edit.
type PolicyPublishResult struct {
	PullRequest githost.PullRequest `json:"pullRequest"`
	Branch      string              `json:"branch"`
	Commit      string              `json:"commit"`
}

// Publish commits the edit to a new branch and opens a pull request into
// the tracked branch. It goes live when an approver merges it.
func (s *Service) Publish(ctx context.Context, name string, req PublishRequest) (PolicyPublishResult, error) {
	if err := s.authorize(ctx, auth.PermissionActionPublish, name); err != nil {
		return PolicyPublishResult{}, err
	}
	changes, err := validatePublish(name, req)
	if err != nil {
		return PolicyPublishResult{}, err
	}
	result, err := s.publish(ctx, name, req, changes)
	outcome, detail := audit.OutcomeSuccess, result.PullRequest.URL
	if err != nil {
		outcome, detail = audit.OutcomeFailure, err.Error()
	}
	audit.Record(ctx, s.cfg.Audit, audit.Event{
		Action: AuditActionPublish, Outcome: outcome, Detail: detail,
		Resource: audit.Resource{Kind: AuditKind, Name: name},
	})
	return result, err
}

func (s *Service) publish(ctx context.Context, name string, req PublishRequest, changes map[string][]byte) (PolicyPublishResult, error) {
	repo, host, err := s.cfg.Open(ctx)
	if err != nil {
		return PolicyPublishResult{}, err
	}
	if err := s.check(ctx, repo, name, req.BaseCommit, changes); err != nil {
		return PolicyPublishResult{}, err
	}

	principal := principalFrom(ctx)
	now := s.cfg.Now().UTC()
	branch, err := publishBranch(name, now)
	if err != nil {
		return PolicyPublishResult{}, err
	}
	committer := s.cfg.Committer
	committer.When = now
	commit, err := repo.Commit(ctx, gitutil.CommitRequest{
		Base: req.BaseCommit, Branch: branch, Files: changes,
		Message:   commitMessage(req.Message, principal),
		Author:    gitutil.Signature{Name: authorName(principal), Email: authorEmail(principal), When: now},
		Committer: committer,
	})
	switch {
	case errors.Is(err, gitutil.ErrNoChanges):
		return PolicyPublishResult{}, fmt.Errorf("%w: the edit changes nothing", ErrConflict)
	case errors.Is(err, gitutil.ErrRefExists):
		return PolicyPublishResult{}, fmt.Errorf("%w: branch %s already exists", ErrConflict, branch)
	case err != nil:
		return PolicyPublishResult{}, err
	}

	title, body, _ := strings.Cut(strings.TrimSpace(req.Message), "\n")
	pr, err := host.OpenPullRequest(ctx, githost.NewPullRequest{
		Title: strings.TrimSpace(title), Head: branch, Base: s.cfg.Branch,
		Body: strings.TrimSpace(body + "\n\nPublished from agentregistry by " + authorName(principal) + "."),
	})
	if err != nil {
		// The branch stays; it is harmless and can be turned into a pull request by hand.
		return PolicyPublishResult{}, fmt.Errorf("pushed branch %s but could not open the pull request: %w", branch, err)
	}
	logger.InfoContext(ctx, "policy change published", "policy", name, "branch", branch, "commit", commit,
		"pull_request", pr.URL, "author", principal.Subject)
	return PolicyPublishResult{PullRequest: pr, Branch: branch, Commit: commit}, nil
}

// check runs the Checker on the policy as it will be after changes (keyed
// by repository path; nil deletes). A policy left without Rego is a
// deletion and isn't checked.
func (s *Service) check(ctx context.Context, repo GitRepo, name, base string, changes map[string][]byte) error {
	if s.cfg.Checker == nil {
		return nil
	}
	after, err := repo.ReadFiles(ctx, base, name)
	if err != nil {
		return err
	}
	for p, content := range changes {
		rel := strings.TrimPrefix(p, name+"/")
		if content == nil {
			delete(after, rel)
		} else {
			after[rel] = content
		}
	}
	if !hasRego(after) {
		return nil
	}
	if err := s.cfg.Checker.CheckFiles(ctx, name, after); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// OnMerged tags each policy a merged pull request changed with its next
// version. A policy already tagged on the merge commit is skipped, so a
// redelivered webhook changes nothing.
func (s *Service) OnMerged(ctx context.Context, event githost.MergeEvent) error {
	if event.BaseBranch != s.cfg.Branch {
		logger.DebugContext(ctx, "ignoring merge into another branch", "branch", event.BaseBranch, "number", event.Number)
		return nil
	}
	repo, host, err := s.cfg.Open(ctx)
	if err != nil {
		return err
	}
	files, err := host.ChangedFiles(ctx, event.Number)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var errs []error
	for _, f := range files {
		name, _, ok := strings.Cut(f, "/")
		if !ok || seen[name] || !policyName.MatchString(name) {
			continue
		}
		seen[name] = true
		if err := s.tag(ctx, repo, name, event); err != nil {
			errs = append(errs, fmt.Errorf("tag %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) tag(ctx context.Context, repo GitRepo, name string, event githost.MergeEvent) error {
	files, err := repo.ReadFiles(ctx, event.MergeCommit, name)
	if err != nil {
		return err
	}
	if !hasRego(files) {
		return nil // not a policy, or deleted by the merge
	}
	for attempt := 1; ; attempt++ {
		tags, err := repo.ListTags(ctx, name+"/v")
		if err != nil {
			return err
		}
		versions := versionTags(name, tags)
		next := 1
		for _, v := range versions {
			if v.tag.Commit == event.MergeCommit {
				return nil
			}
		}
		if len(versions) > 0 {
			next = versions[0].n + 1
		}
		tag := name + "/v" + strconv.Itoa(next)
		err = repo.PushTag(ctx, tag, event.MergeCommit)
		if errors.Is(err, gitutil.ErrRefExists) && attempt < maxTagAttempts {
			continue // another replica or delivery took that number
		}
		outcome, detail := audit.OutcomeSuccess, fmt.Sprintf("%s at %s (pull request #%d)", tag, event.MergeCommit, event.Number)
		if err != nil {
			outcome, detail = audit.OutcomeFailure, err.Error()
		}
		audit.Record(ctx, s.cfg.Audit, audit.Event{
			Action: AuditActionTag, Outcome: outcome, Detail: detail, Source: "webhook",
			Resource: audit.Resource{Kind: AuditKind, Name: name, Tag: "v" + strconv.Itoa(next)},
		})
		if err == nil {
			logger.InfoContext(ctx, "policy version tagged", "policy", name, "tag", tag, "commit", event.MergeCommit, "number", event.Number)
		}
		return err
	}
}

// WebhookHandler receives the git host's webhook deliveries. It
// authenticates them by signature, not by a token, and tags merged changes.
func (s *Service) WebhookHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
		if err != nil || len(body) > maxWebhookBody {
			http.Error(w, "unreadable or oversized body", http.StatusBadRequest)
			return
		}
		// The git host may give up waiting; tagging finishes regardless.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), webhookTimeout)
		defer cancel()
		_, host, err := s.cfg.Open(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "policy webhook: connecting to the git host", "error", err)
			http.Error(w, "git host unavailable", http.StatusServiceUnavailable)
			return
		}
		event, ok, err := host.ParseWebhook(r.Header, body)
		switch {
		case errors.Is(err, githost.ErrBadSignature):
			logger.WarnContext(ctx, "policy webhook: signature rejected", "remote", r.RemoteAddr)
			http.Error(w, "signature rejected", http.StatusUnauthorized)
			return
		case err != nil:
			http.Error(w, "malformed event", http.StatusBadRequest)
			return
		case !ok:
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := s.OnMerged(ctx, event); err != nil {
			logger.ErrorContext(ctx, "policy webhook: tagging failed", "number", event.Number, "commit", event.MergeCommit, "error", err)
			// A failure is shown in the host's delivery log, from where it can be redelivered.
			http.Error(w, "tagging failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// validatePublish checks the request and returns its changes keyed by
// repository path.
func validatePublish(name string, req PublishRequest) (map[string][]byte, error) {
	msg := strings.TrimSpace(req.Message)
	if msg == "" {
		return nil, fmt.Errorf("%w: a commit message is required", ErrInvalid)
	}
	if len(msg) > maxMessageBytes {
		return nil, fmt.Errorf("%w: the commit message is longer than %d bytes", ErrInvalid, maxMessageBytes)
	}
	if len(req.Files) == 0 {
		return nil, fmt.Errorf("%w: no files to publish", ErrInvalid)
	}
	if len(req.Files) > maxPublishFiles {
		return nil, fmt.Errorf("%w: more than %d files", ErrInvalid, maxPublishFiles)
	}
	changes := make(map[string][]byte, len(req.Files))
	total := 0
	for rel, content := range req.Files {
		if err := checkDraftPath(rel); err != nil {
			return nil, err
		}
		if content == nil {
			changes[name+"/"+rel] = nil
			continue
		}
		if len(*content) > maxFileBytes {
			return nil, fmt.Errorf("%w: file %q is larger than %d bytes", ErrInvalid, rel, maxFileBytes)
		}
		if total += len(*content); total > maxPublishBytes {
			return nil, fmt.Errorf("%w: the files are larger than %d bytes together", ErrInvalid, maxPublishBytes)
		}
		changes[name+"/"+rel] = []byte(*content)
	}
	return changes, nil
}

func publishBranch(name string, now time.Time) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s/%s-%s", publishBranchRoot, name, now.Format("20060102-150405"), hex.EncodeToString(b[:])), nil
}

func principalFrom(ctx context.Context) auth.Principal {
	if s, ok := auth.AuthSessionFrom(ctx); ok && s != nil {
		return s.Principal()
	}
	return auth.Principal{}
}

func authorName(p auth.Principal) string {
	switch {
	case p.Username != "":
		return p.Username
	case p.Subject != "":
		return p.Subject
	default:
		return "anonymous"
	}
}

func authorEmail(p auth.Principal) string {
	if email, ok := p.Claims["email"].(string); ok && strings.Contains(email, "@") && !strings.ContainsAny(email, "<>\n") {
		return email
	}
	host := "agentregistry"
	if u, err := url.Parse(p.Issuer); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	local := strings.Map(func(r rune) rune {
		if r == '<' || r == '>' || r == '@' || r == '\n' || r == ' ' {
			return '-'
		}
		return r
	}, authorName(p))
	return local + "@" + host
}

// commitMessage appends who published the change, by verified identity.
func commitMessage(msg string, p auth.Principal) string {
	msg = strings.TrimSpace(msg) + "\n\nPublished-via: agentregistry\n"
	if p.Subject != "" {
		msg += "Published-by: " + p.Subject + " (" + p.Issuer + ")\n"
	}
	return msg
}
