package policies

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/opaeval"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

// Engine formats, checks, evaluates and tests drafts; *opaeval.Engine
// implements it.
type Engine interface {
	Format(file string, src []byte) ([]byte, []opaeval.RegoProblem)
	Check(policy string, files map[string][]byte) []opaeval.RegoProblem
	Evaluate(ctx context.Context, req opaeval.EvalRequest) (opaeval.RegoEvalResult, error)
	Test(ctx context.Context, policy string, files map[string][]byte, data map[string]any) (opaeval.RegoTestReport, error)
}

// ErrNoEngine is a tool call on a service configured without an Engine.
var ErrNoEngine = errors.New("the policy engine is not configured")

// PolicyDraft is the editor's working copy of a policy, paths relative to it.
type PolicyDraft map[string]string

// PolicyFormatResult is a formatted file, or why it couldn't be formatted.
type PolicyFormatResult struct {
	Content  string                `json:"content,omitempty"`
	Problems []opaeval.RegoProblem `json:"problems"`
}

// Format formats one Rego file of the policy.
func (s *Service) Format(ctx context.Context, name, file, content string) (PolicyFormatResult, error) {
	if err := s.tool(ctx, name); err != nil {
		return PolicyFormatResult{}, err
	}
	if err := checkDraftPath(file); err != nil || !strings.HasSuffix(file, ".rego") {
		return PolicyFormatResult{}, fmt.Errorf("%w: %q is not a .rego file of the policy", ErrInvalid, file)
	}
	out, probs := s.cfg.Engine.Format(path.Join(name, file), []byte(content))
	return PolicyFormatResult{Content: string(out), Problems: nonNil(probs)}, nil
}

// CheckDraft parses and compiles the draft and returns its problems.
func (s *Service) CheckDraft(ctx context.Context, name string, draft PolicyDraft) ([]opaeval.RegoProblem, error) {
	files, err := s.draft(ctx, name, draft)
	if err != nil {
		return nil, err
	}
	return nonNil(s.cfg.Engine.Check(name, files)), nil
}

// EvaluateDraft runs a query against the draft.
func (s *Service) EvaluateDraft(ctx context.Context, name string, draft PolicyDraft, query string, input any, data map[string]any) (opaeval.RegoEvalResult, error) {
	files, err := s.draft(ctx, name, draft)
	if err != nil {
		return opaeval.RegoEvalResult{}, err
	}
	res, err := s.cfg.Engine.Evaluate(ctx, opaeval.EvalRequest{Policy: name, Files: files, Query: query, Input: input, Data: data})
	if errors.Is(err, opaeval.ErrTimeout) {
		return res, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	res.Problems = nonNil(res.Problems)
	return res, err
}

// TestDraft runs the draft's tests.
func (s *Service) TestDraft(ctx context.Context, name string, draft PolicyDraft, data map[string]any) (opaeval.RegoTestReport, error) {
	files, err := s.draft(ctx, name, draft)
	if err != nil {
		return opaeval.RegoTestReport{}, err
	}
	report, err := s.cfg.Engine.Test(ctx, name, files, data)
	if errors.Is(err, opaeval.ErrTimeout) {
		return report, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	report.Problems = nonNil(report.Problems)
	return report, err
}

// checkFiles is the default Checker: the Engine's check, for Publish.
func (s *Service) checkFiles(_ context.Context, name string, files map[string][]byte) error {
	probs := s.cfg.Engine.Check(name, files)
	if len(probs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(probs))
	for _, p := range probs {
		msgs = append(msgs, p.String())
	}
	return errors.New(strings.Join(msgs, "; "))
}

// tool authorizes a tool call: the editor's tools need read on the policy.
func (s *Service) tool(ctx context.Context, name string) error {
	if s.cfg.Engine == nil {
		return ErrNoEngine
	}
	return s.authorize(ctx, auth.PermissionActionRead, name)
}

func (s *Service) draft(ctx context.Context, name string, draft PolicyDraft) (map[string][]byte, error) {
	if err := s.tool(ctx, name); err != nil {
		return nil, err
	}
	if len(draft) > maxPublishFiles {
		return nil, fmt.Errorf("%w: more than %d files", ErrInvalid, maxPublishFiles)
	}
	files := make(map[string][]byte, len(draft))
	for rel, content := range draft {
		if err := checkDraftPath(rel); err != nil {
			return nil, err
		}
		files[rel] = []byte(content)
	}
	return files, nil
}

// checkDraftPath accepts a clean path inside the policy naming a .rego
// file or data.json (OPAL loads only data.json files, not data.yaml).
func checkDraftPath(rel string) error {
	clean := path.Clean(rel)
	if rel == "" || path.IsAbs(rel) || clean != rel || clean == ".." || strings.HasPrefix(clean, "../") ||
		strings.ContainsAny(rel, "\\\x00") || strings.HasPrefix(path.Base(rel), ".") {
		return fmt.Errorf("%w: file path %q must be a clean relative path inside the policy", ErrInvalid, rel)
	}
	if !strings.HasSuffix(rel, ".rego") && !isDataFile(rel) {
		return fmt.Errorf("%w: file %q must be a .rego file or data.json", ErrInvalid, rel)
	}
	return nil
}

func nonNil(p []opaeval.RegoProblem) []opaeval.RegoProblem {
	if p == nil {
		return []opaeval.RegoProblem{}
	}
	return p
}
