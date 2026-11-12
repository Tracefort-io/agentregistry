package resource

import (
	"context"
	"strings"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
)

// maxAuditDetail bounds the reason stored with a failed operation.
const maxAuditDetail = 500

// recordOutcome records an apply or delete that reached the pipeline: what
// it changed, or why it was denied or failed. status is the result on
// success (created, configured, unchanged, deleted).
func recordOutcome(ctx context.Context, r audit.Recorder, action, source string, res audit.Resource, status string, ae *applyError) {
	if r == nil {
		return
	}
	e := audit.Event{Action: action, Resource: res, Source: source}
	switch {
	case ae == nil:
		e.Outcome, e.Detail = audit.OutcomeSuccess, status
	case ae.Stage == stageAuth:
		// Authorization errors carry only a client-safe reason.
		e.Outcome, e.Detail = audit.OutcomeDenied, ae.Err.Error()
	default:
		e.Outcome, e.Detail = audit.OutcomeFailure, string(ae.Stage)
		// A Secret's validation error could quote its data; keep the stage only.
		if res.Kind != v1alpha1.KindSecret && ae.Err != nil {
			e.Detail += ": " + ae.Err.Error()
		}
	}
	if len(e.Detail) > maxAuditDetail {
		// Cutting may split a multi-byte character; Postgres rejects that.
		e.Detail = strings.ToValidUTF8(e.Detail[:maxAuditDetail], "")
	}
	audit.Record(ctx, r, e)
}
