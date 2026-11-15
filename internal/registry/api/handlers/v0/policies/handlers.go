// Package policies serves the policy endpoints under /v0/policies: Rego
// policies read live from the policy repository, their versions, and
// publishing edits as pull (merge) requests. Who may read or publish a
// policy is decided by the AuthZEN PDP, in the service.
package policies

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	svc "github.com/agentregistry-dev/agentregistry/internal/registry/policies"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/githost"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/opaeval"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var logger = logging.New("policies-api")

// Service is what the handlers need from the policies component.
type Service interface {
	List(ctx context.Context) ([]svc.PolicySummary, error)
	Get(ctx context.Context, name, ref string) (svc.Policy, error)
	Versions(ctx context.Context, name string) ([]svc.PolicyVersion, error)
	Diff(ctx context.Context, name, from, to string) ([]svc.PolicyChange, error)
	Pending(ctx context.Context, name string) ([]githost.PullRequest, error)
	Status(ctx context.Context, name string) (svc.PolicyStatus, error)
	Publish(ctx context.Context, name string, req svc.PublishRequest) (svc.PolicyPublishResult, error)
	Format(ctx context.Context, name, file, content string) (svc.PolicyFormatResult, error)
	CheckDraft(ctx context.Context, name string, draft svc.PolicyDraft) ([]opaeval.RegoProblem, error)
	EvaluateDraft(ctx context.Context, name string, draft svc.PolicyDraft, query string, input any, data map[string]any) (opaeval.RegoEvalResult, error)
	TestDraft(ctx context.Context, name string, draft svc.PolicyDraft, data map[string]any) (opaeval.RegoTestReport, error)
}

// ProblemsBody is the POST /v0/policies/{name}/check response.
type ProblemsBody struct {
	Problems []opaeval.RegoProblem `json:"problems"`
}

type formatInput struct {
	Name string `path:"name" maxLength:"63"`
	Body struct {
		Path    string `json:"path" maxLength:"512" doc:"The file's path inside the policy"`
		Content string `json:"content"`
	}
}

type draftInput struct {
	Name string `path:"name" maxLength:"63"`
	Body struct {
		Files svc.PolicyDraft `json:"files" doc:"The policy's files by path inside the policy"`
		Data  map[string]any  `json:"data,omitempty" doc:"Data merged over what the policy's data files provide"`
	}
}

type evaluateInput struct {
	Name string `path:"name" maxLength:"63"`
	Body struct {
		Files svc.PolicyDraft `json:"files" doc:"The policy's files by path inside the policy"`
		Query string          `json:"query,omitempty" maxLength:"4096" doc:"A Rego query; empty evaluates the policy's package"`
		Input any             `json:"input,omitempty" doc:"The value of input"`
		Data  map[string]any  `json:"data,omitempty" doc:"Data merged over what the policy's data files provide"`
	}
}

// Config wires the endpoints.
type Config struct {
	Service Service
}

// PolicyListBody is the GET /v0/policies response.
type PolicyListBody struct {
	Policies []svc.PolicySummary `json:"policies"`
}

// VersionsBody is the GET /v0/policies/{name}/versions response.
type VersionsBody struct {
	Versions []svc.PolicyVersion `json:"versions"`
}

// DiffBody is the GET /v0/policies/{name}/diff response.
type DiffBody struct {
	Changes []svc.PolicyChange `json:"changes"`
}

// PendingBody is the GET /v0/policies/{name}/pending response.
type PendingBody struct {
	PullRequests []githost.PullRequest `json:"pullRequests"`
}

type nameInput struct {
	Name string `path:"name" maxLength:"63" doc:"Policy name: the repository's top-level directory"`
}

type getInput struct {
	Name string `path:"name" maxLength:"63"`
	Ref  string `query:"ref" maxLength:"200" doc:"A version (v3) or commit; the tracked branch when empty"`
}

type diffInput struct {
	Name string `path:"name" maxLength:"63"`
	From string `query:"from" maxLength:"200" doc:"A version or commit; the tracked branch when empty"`
	To   string `query:"to" maxLength:"200" doc:"A version or commit; the tracked branch when empty"`
}

type publishInput struct {
	Name string `path:"name" maxLength:"63"`
	Body struct {
		BaseCommit string `json:"baseCommit" pattern:"^[0-9a-f]{40}$" doc:"The commit the edit started from (the policy's commit)"`
		// Files maps paths relative to the policy to their new contents;
		// null deletes the file.
		Files   map[string]*string `json:"files" doc:"Changed files by path inside the policy; null deletes"`
		Message string             `json:"message" minLength:"1" maxLength:"8192" doc:"Commit message; its first line titles the pull request"`
	}
}

// Register adds the endpoints under pathPrefix.
func Register(api huma.API, pathPrefix string, cfg Config) {
	tags := []string{"policies"}
	base := pathPrefix + "/policies"

	huma.Register(api, huma.Operation{
		OperationID: "list-policies", Method: http.MethodGet, Path: base,
		Summary: "List policies", Tags: tags,
		Description: "The policies on the tracked branch that the caller may read, read live from the repository.",
	}, func(ctx context.Context, _ *struct{}) (*types.Response[PolicyListBody], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		list, err := cfg.Service.List(ctx)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[PolicyListBody]{Body: PolicyListBody{Policies: list}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-policy", Method: http.MethodGet, Path: base + "/{name}",
		Summary: "Get a policy's files", Tags: tags,
	}, func(ctx context.Context, in *getInput) (*types.Response[svc.Policy], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		p, err := cfg.Service.Get(ctx, in.Name, in.Ref)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[svc.Policy]{Body: p}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-policy-versions", Method: http.MethodGet, Path: base + "/{name}/versions",
		Summary: "List a policy's versions", Tags: tags,
		Description: "The policy's <name>/v<N> tags, newest first: one per merged change.",
	}, func(ctx context.Context, in *nameInput) (*types.Response[VersionsBody], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		v, err := cfg.Service.Versions(ctx, in.Name)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[VersionsBody]{Body: VersionsBody{Versions: v}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "diff-policy", Method: http.MethodGet, Path: base + "/{name}/diff",
		Summary: "Compare two versions of a policy", Tags: tags,
	}, func(ctx context.Context, in *diffInput) (*types.Response[DiffBody], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		changes, err := cfg.Service.Diff(ctx, in.Name, in.From, in.To)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[DiffBody]{Body: DiffBody{Changes: changes}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-policy-pending", Method: http.MethodGet, Path: base + "/{name}/pending",
		Summary: "List open pull requests that change a policy", Tags: tags,
	}, func(ctx context.Context, in *nameInput) (*types.Response[PendingBody], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		prs, err := cfg.Service.Pending(ctx, in.Name)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[PendingBody]{Body: PendingBody{PullRequests: prs}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-policy-status", Method: http.MethodGet, Path: base + "/{name}/status",
		Summary: "Show which version of a policy OPA has loaded", Tags: tags,
	}, func(ctx context.Context, in *nameInput) (*types.Response[svc.PolicyStatus], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		st, err := cfg.Service.Status(ctx, in.Name)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[svc.PolicyStatus]{Body: st}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "publish-policy", Method: http.MethodPost, Path: base + "/{name}/publish",
		Summary: "Publish a policy change as a pull request", Tags: tags,
		Description: "Commits the changed files on top of baseCommit to a new branch and opens a pull (merge) request " +
			"into the tracked branch. The change goes live when an approver merges it.",
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *publishInput) (*types.Response[svc.PolicyPublishResult], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		res, err := cfg.Service.Publish(ctx, in.Name, svc.PublishRequest{
			BaseCommit: in.Body.BaseCommit, Files: in.Body.Files, Message: in.Body.Message,
		})
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[svc.PolicyPublishResult]{Body: res}, nil
	})

	// The editor's tools run on the caller's draft, in the registry; none
	// of them writes anything.
	huma.Register(api, huma.Operation{
		OperationID: "format-policy-file", Method: http.MethodPost, Path: base + "/{name}/format",
		Summary: "Format a Rego file of a draft", Tags: tags,
	}, func(ctx context.Context, in *formatInput) (*types.Response[svc.PolicyFormatResult], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		res, err := cfg.Service.Format(ctx, in.Name, in.Body.Path, in.Body.Content)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[svc.PolicyFormatResult]{Body: res}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "check-policy-draft", Method: http.MethodPost, Path: base + "/{name}/check",
		Summary: "Parse and compile a draft", Tags: tags,
	}, func(ctx context.Context, in *draftInput) (*types.Response[ProblemsBody], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		probs, err := cfg.Service.CheckDraft(ctx, in.Name, in.Body.Files)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[ProblemsBody]{Body: ProblemsBody{Problems: probs}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "evaluate-policy-draft", Method: http.MethodPost, Path: base + "/{name}/evaluate",
		Summary: "Evaluate a query against a draft", Tags: tags,
		Description: "Runs with network built-ins removed and a time limit.",
	}, func(ctx context.Context, in *evaluateInput) (*types.Response[opaeval.RegoEvalResult], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		res, err := cfg.Service.EvaluateDraft(ctx, in.Name, in.Body.Files, in.Body.Query, in.Body.Input, in.Body.Data)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[opaeval.RegoEvalResult]{Body: res}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "test-policy-draft", Method: http.MethodPost, Path: base + "/{name}/test",
		Summary: "Run a draft's tests", Tags: tags,
		Description: "Runs the test_ rules with network built-ins removed and a time limit.",
	}, func(ctx context.Context, in *draftInput) (*types.Response[opaeval.RegoTestReport], error) {
		if err := signedIn(ctx); err != nil {
			return nil, err
		}
		report, err := cfg.Service.TestDraft(ctx, in.Name, in.Body.Files, in.Body.Data)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[opaeval.RegoTestReport]{Body: report}, nil
	})
}

// signedIn refuses anonymous callers: publishing is attributed to the
// caller, and reads are checked against them.
func signedIn(ctx context.Context) error {
	s, ok := auth.AuthSessionFrom(ctx)
	if !ok || s == nil || !s.Principal().IsAuthenticated() {
		return huma.Error401Unauthorized("policies need a signed-in caller")
	}
	return nil
}

// mapError turns service errors into responses without passing on the
// git host's internals.
func mapError(ctx context.Context, err error) error {
	var status huma.StatusError
	switch {
	case errors.As(err, &status):
		return err
	case errors.Is(err, auth.ErrForbidden):
		return huma.Error403Forbidden("not permitted")
	case errors.Is(err, svc.ErrNotFound):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, svc.ErrInvalid):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.Is(err, svc.ErrConflict):
		return huma.Error409Conflict(err.Error())
	}
	logger.ErrorContext(ctx, "policies request failed", "error", err)
	return huma.Error502BadGateway("the policy repository is unavailable")
}
