package types

import (
	"context"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

// ApprovalStager turns a write that authorization refused, but that may be
// approved, into an approval request. The registry applies the change
// itself once the request is approved.
type ApprovalStager interface {
	// Stage returns the request's ID and staged=true when denial is a
	// denial that may be approved; staged=false leaves the refusal as is.
	Stage(ctx context.Context, in ApprovalStageInput) (requestID string, staged bool, err error)
}

// ApprovalStageInput is a write that authorization refused.
type ApprovalStageInput struct {
	// Verb is "apply" or "delete".
	Verb      string
	Kind      string
	Namespace string
	Name      string
	Tag       string
	// Object is the document to apply; nil for a delete.
	Object v1alpha1.Object
	// Denial is the authorization error.
	Denial error
}

type approvalIDKey struct{}

// WithApprovalID marks ctx as carrying out a change approved by approval
// id: authorization presents the approval to the PDP.
func WithApprovalID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, approvalIDKey{}, id)
}

// ApprovalIDFrom returns the approval set by WithApprovalID.
func ApprovalIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(approvalIDKey{}).(string)
	return id
}
