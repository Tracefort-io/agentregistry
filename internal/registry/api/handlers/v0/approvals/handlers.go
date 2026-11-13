// Package approvals serves the approval endpoints: requesters follow and
// cancel their held changes under /v0/approvals, and approvers review and
// decide under /v0/approval-reviews. Who must approve what is decided by
// the AuthZEN PDP's policy; these handlers only carry requests to it.
package approvals

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	svc "github.com/agentregistry-dev/agentregistry/internal/registry/approvals"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var logger = logging.New("approvals-api")

// Service is what the handlers need from the approvals component.
type Service interface {
	List(ctx context.Context, subject string, all bool, statuses []string, limit int, cursor string) ([]v1alpha1store.ApprovalRequest, string, error)
	Get(ctx context.Context, id, subject string, admin bool) (v1alpha1store.ApprovalRequest, error)
	Cancel(ctx context.Context, id, subject string, admin bool, reason string) (v1alpha1store.ApprovalRequest, error)
	ReviewList(ctx context.Context, approverToken string) ([]svc.ApprovalReview, error)
	ReviewGet(ctx context.Context, approverToken, id string) (svc.ApprovalReview, error)
	Decide(ctx context.Context, approverToken, id, decision, comment string) (svc.ApprovalReview, error)
}

// Config wires the endpoints.
type Config struct {
	Service Service
	// IsAdmin reports a registry admin, who sees and may cancel every request.
	IsAdmin func(ctx context.Context) bool
}

// ApprovalListBody is the GET /v0/approvals response.
type ApprovalListBody struct {
	Requests   []v1alpha1store.ApprovalRequest `json:"requests"`
	NextCursor string                          `json:"nextCursor,omitempty"`
}

// ApprovalReviewsBody is the GET /v0/approval-reviews response.
type ApprovalReviewsBody struct {
	Reviews []svc.ApprovalReview `json:"reviews"`
}

type listInput struct {
	Status string `query:"status" doc:"Comma-separated states, for example pending,approved"`
	All    bool   `query:"all" doc:"Every requester's requests (registry admins only)"`
	Limit  int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
	Cursor string `query:"cursor"`
}

type idInput struct {
	ID string `path:"id" maxLength:"200"`
}

type cancelInput struct {
	ID   string `path:"id" maxLength:"200"`
	Body struct {
		Reason string `json:"reason,omitempty" maxLength:"1000"`
	}
}

type tokenInput struct {
	Authorization string `header:"Authorization"`
}

type reviewInput struct {
	ID            string `path:"id" maxLength:"200"`
	Authorization string `header:"Authorization"`
}

type decideInput struct {
	ID            string `path:"id" maxLength:"200"`
	Authorization string `header:"Authorization"`
	Body          struct {
		Decision string `json:"decision" enum:"approve,deny"`
		Comment  string `json:"comment,omitempty" maxLength:"2000"`
	}
}

// Register adds the endpoints under pathPrefix.
func Register(api huma.API, pathPrefix string, cfg Config) {
	isAdmin := func(ctx context.Context) bool { return cfg.IsAdmin != nil && cfg.IsAdmin(ctx) }

	huma.Register(api, huma.Operation{
		OperationID: "list-approval-requests", Method: http.MethodGet, Path: pathPrefix + "/approvals",
		Summary: "List changes held for approval", Tags: []string{"approvals"},
		Description: "The caller's own requests, newest first; all=true lists everyone's for a registry admin.",
	}, func(ctx context.Context, in *listInput) (*types.Response[ApprovalListBody], error) {
		subject, err := callerSubject(ctx)
		if err != nil {
			return nil, err
		}
		var statuses []string
		for st := range strings.SplitSeq(in.Status, ",") {
			if st = strings.TrimSpace(st); st != "" {
				statuses = append(statuses, st)
			}
		}
		reqs, next, err := cfg.Service.List(ctx, subject, in.All && isAdmin(ctx), statuses, in.Limit, in.Cursor)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		if reqs == nil {
			reqs = []v1alpha1store.ApprovalRequest{}
		}
		return &types.Response[ApprovalListBody]{Body: ApprovalListBody{Requests: reqs, NextCursor: next}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-approval-request", Method: http.MethodGet, Path: pathPrefix + "/approvals/{id}",
		Summary: "Get a change held for approval", Tags: []string{"approvals"},
	}, func(ctx context.Context, in *idInput) (*types.Response[v1alpha1store.ApprovalRequest], error) {
		subject, err := callerSubject(ctx)
		if err != nil {
			return nil, err
		}
		r, err := cfg.Service.Get(ctx, in.ID, subject, isAdmin(ctx))
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[v1alpha1store.ApprovalRequest]{Body: r}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "cancel-approval-request", Method: http.MethodPost, Path: pathPrefix + "/approvals/{id}/cancel",
		Summary: "Withdraw a change held for approval", Tags: []string{"approvals"},
	}, func(ctx context.Context, in *cancelInput) (*types.Response[v1alpha1store.ApprovalRequest], error) {
		subject, err := callerSubject(ctx)
		if err != nil {
			return nil, err
		}
		r, err := cfg.Service.Cancel(ctx, in.ID, subject, isAdmin(ctx), in.Body.Reason)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[v1alpha1store.ApprovalRequest]{Body: r}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-approval-reviews", Method: http.MethodGet, Path: pathPrefix + "/approval-reviews",
		Summary: "List changes awaiting the caller's approval", Tags: []string{"approvals"},
		Description: "The access request service decides, from the caller's token, which requests they may review.",
	}, func(ctx context.Context, in *tokenInput) (*types.Response[ApprovalReviewsBody], error) {
		token, err := bearer(in.Authorization)
		if err != nil {
			return nil, err
		}
		reviews, err := cfg.Service.ReviewList(ctx, token)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		if reviews == nil {
			reviews = []svc.ApprovalReview{}
		}
		return &types.Response[ApprovalReviewsBody]{Body: ApprovalReviewsBody{Reviews: reviews}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-approval-review", Method: http.MethodGet, Path: pathPrefix + "/approval-reviews/{id}",
		Summary: "Get a change awaiting the caller's approval", Tags: []string{"approvals"},
	}, func(ctx context.Context, in *reviewInput) (*types.Response[svc.ApprovalReview], error) {
		token, err := bearer(in.Authorization)
		if err != nil {
			return nil, err
		}
		rv, err := cfg.Service.ReviewGet(ctx, token, in.ID)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[svc.ApprovalReview]{Body: rv}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "decide-approval-review", Method: http.MethodPost, Path: pathPrefix + "/approval-reviews/{id}/decision",
		Summary: "Approve or deny a held change", Tags: []string{"approvals"},
		Description: "An approved change is applied by the registry as soon as the request is approved.",
	}, func(ctx context.Context, in *decideInput) (*types.Response[svc.ApprovalReview], error) {
		token, err := bearer(in.Authorization)
		if err != nil {
			return nil, err
		}
		rv, err := cfg.Service.Decide(ctx, token, in.ID, in.Body.Decision, in.Body.Comment)
		if err != nil {
			return nil, mapError(ctx, err)
		}
		return &types.Response[svc.ApprovalReview]{Body: rv}, nil
	})
}

func callerSubject(ctx context.Context) (string, error) {
	s, ok := auth.AuthSessionFrom(ctx)
	if !ok || s == nil || !s.Principal().IsAuthenticated() {
		return "", huma.Error401Unauthorized("approvals need a signed-in caller")
	}
	return s.Principal().Subject, nil
}

func bearer(header string) (string, error) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", huma.Error401Unauthorized("approvals need a bearer token")
	}
	return strings.TrimSpace(token), nil
}

// mapError turns service errors into responses without passing on the
// service's internals.
func mapError(ctx context.Context, err error) error {
	var problem *svc.ProblemError
	switch {
	case errors.Is(err, v1alpha1store.ErrApprovalNotFound), errors.Is(err, svc.ErrNotFound):
		return huma.Error404NotFound("approval request not found")
	case errors.Is(err, svc.ErrNotPending):
		return huma.Error409Conflict(err.Error())
	case errors.As(err, &problem) && problem.Status == http.StatusForbidden:
		return huma.Error403Forbidden("not permitted to review this request")
	case errors.As(err, &problem) && problem.Status == http.StatusConflict:
		return huma.Error409Conflict("the request was already decided, or you already voted")
	case errors.As(err, &problem) && problem.Status == http.StatusUnauthorized:
		return huma.Error401Unauthorized("the access request service did not accept your token")
	case errors.As(err, &problem) && problem.Status == http.StatusBadRequest:
		return huma.Error400BadRequest("the access request service refused the request")
	}
	logger.ErrorContext(ctx, "approvals request failed", "error", err)
	return huma.Error502BadGateway("the access request service is unavailable")
}
