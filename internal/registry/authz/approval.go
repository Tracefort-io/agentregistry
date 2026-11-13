package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// Context members for approvals (OpenID AuthZEN Access Request and
// Approval Profile).
const (
	// ContextDocumentSHA256 is the SHA-256 of the document being applied.
	// A policy that binds it (binding_context_members) ties an approval
	// to exactly the reviewed content.
	ContextDocumentSHA256 = "document_sha256"
	// ContextApproval carries an approval when applying an approved change.
	ContextApproval = "approval"
)

// ApprovalRequired is a denial the PDP marked requestable: the caller may
// ask for the change to be approved. It is still a 403 and matches
// auth.ErrForbidden.
type ApprovalRequired struct {
	err *Error
	// Request is the evaluation the PDP refused. An access request must
	// name the same subject, resource, action and bound context.
	Request authzen.EvaluationRequest
	// Denial is the denial an access request carries: the PDP's
	// binding_token, expires_at, evaluation_id, template and reason.
	Denial map[string]any
}

func (e *ApprovalRequired) Error() string { return e.err.Error() }

// Unwrap exposes the 403 to StatusOf and errors.Is.
func (e *ApprovalRequired) Unwrap() error { return e.err }

// requestable returns an *ApprovalRequired when the PDP's denial carries
// context.access_request with a binding token, and nil otherwise.
func requestable(req authzen.EvaluationRequest, respCtx map[string]any, detail string) error {
	ar, _ := respCtx["access_request"].(map[string]any)
	token, _ := ar["binding_token"].(string)
	if token == "" {
		return nil
	}
	denial := map[string]any{"binding_token": token}
	for _, k := range []string{"expires_at", "template"} {
		if v, ok := ar[k].(string); ok && v != "" {
			denial[k] = v
		}
	}
	for _, k := range []string{"evaluation_id", "evaluated_at", "reason"} {
		if v, ok := respCtx[k].(string); ok && v != "" {
			denial[k] = v
		}
	}
	return &ApprovalRequired{err: forbidden("approval required: " + detail), Request: req, Denial: denial}
}

// withDocument adds the document's hash to an apply's context. A Secret's
// hash is not sent: it would be derived from its values.
func withDocument(c authzen.Context, obj v1alpha1.Object) authzen.Context {
	if obj == nil || obj.GetKind() == v1alpha1.KindSecret {
		return c
	}
	if sum, err := DocumentSHA256(obj); err == nil {
		c[ContextDocumentSHA256] = sum
	}
	return c
}

// DocumentSHA256 is the hex SHA-256 of obj's JSON encoding.
func DocumentSHA256(obj v1alpha1.Object) (string, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("encode document: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// withApproval presents the approval the change was approved by, if any.
func withApproval(ctx context.Context, c authzen.Context) authzen.Context {
	if id := types.ApprovalIDFrom(ctx); id != "" {
		c[ContextApproval] = map[string]any{"id": id}
	}
	return c
}
