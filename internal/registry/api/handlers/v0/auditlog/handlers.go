// Package auditlog serves GET /v0/audit: the audit log, for registry admins.
package auditlog

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var logger = logging.New("audit-api")

// Config wires the endpoint.
type Config struct {
	// Lister reads the stored events.
	Lister audit.Lister
	// IsAdmin reports whether the caller may read the audit log.
	IsAdmin func(ctx context.Context) bool
}

// EventsBody is the GET /v0/audit response.
type EventsBody struct {
	Events     []audit.Event `json:"events"`
	NextCursor string        `json:"nextCursor,omitempty" doc:"Pass as cursor for the next page; absent on the last page"`
}

type input struct {
	Actor     string `query:"actor" doc:"Subject or username of the caller"`
	Action    string `query:"action" enum:"apply,delete,read,list," doc:"Action taken"`
	Outcome   string `query:"outcome" enum:"success,denied,failure," doc:"Outcome"`
	Kind      string `query:"kind" doc:"Resource kind, for example Agent"`
	Namespace string `query:"namespace"`
	Name      string `query:"name"`
	Since     string `query:"since" doc:"Earliest time, RFC 3339"`
	Until     string `query:"until" doc:"Time before which events are returned, RFC 3339"`
	Limit     int    `query:"limit" minimum:"1" maximum:"500" default:"50"`
	Cursor    string `query:"cursor" doc:"nextCursor from the previous page"`
}

// Register adds GET {pathPrefix}/audit.
func Register(api huma.API, pathPrefix string, cfg Config) {
	huma.Register(api, huma.Operation{
		OperationID: "list-audit-events",
		Method:      http.MethodGet,
		Path:        pathPrefix + "/audit",
		Summary:     "List audit events",
		Description: "Who applied or deleted what, and which reads were refused, newest first. Registry admins only.",
		Tags:        []string{"audit"},
	}, func(ctx context.Context, in *input) (*types.Response[EventsBody], error) {
		if cfg.IsAdmin == nil || !cfg.IsAdmin(ctx) {
			return nil, huma.Error403Forbidden("reading the audit log requires registry admin")
		}
		q := audit.Query{
			Actor: in.Actor, Action: in.Action, Outcome: in.Outcome,
			Kind: in.Kind, Namespace: in.Namespace, Name: in.Name,
			Limit: in.Limit, Cursor: in.Cursor,
		}
		var err error
		if q.Since, err = parseTime("since", in.Since); err != nil {
			return nil, err
		}
		if q.Until, err = parseTime("until", in.Until); err != nil {
			return nil, err
		}
		events, next, err := cfg.Lister.ListAuditEvents(ctx, q)
		if errors.Is(err, audit.ErrInvalidCursor) {
			return nil, huma.Error400BadRequest("invalid cursor")
		}
		if err != nil {
			// Logged, not returned: the cause may name database internals.
			logger.ErrorContext(ctx, "listing audit events failed", "error", err)
			return nil, huma.Error500InternalServerError("listing audit events failed")
		}
		if events == nil {
			events = []audit.Event{}
		}
		return &types.Response[EventsBody]{Body: EventsBody{Events: events, NextCursor: next}}, nil
	})
}

func parseTime(field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, huma.Error400BadRequest(field + " must be an RFC 3339 time, for example 2026-11-11T09:00:00Z")
	}
	return t, nil
}
