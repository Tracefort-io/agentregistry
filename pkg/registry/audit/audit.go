// Package audit records who did what in the registry: every apply and delete,
// and every read the authorization service refused. A Recorder receives each
// Event; the registry stores them in Postgres and can export them over
// OpenTelemetry.
package audit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

// Actions recorded.
const (
	ActionApply  = "apply"
	ActionDelete = "delete"
	ActionRead   = "read"
	ActionList   = "list"
	// ActionRequestApproval: a change that needs approval was submitted
	// for it and held.
	ActionRequestApproval = "request-approval"
)

// Outcomes recorded.
const (
	// OutcomeSuccess: the operation took effect.
	OutcomeSuccess = "success"
	// OutcomeDenied: authentication or authorization refused it, including a
	// PDP that could not decide.
	OutcomeDenied = "denied"
	// OutcomeFailure: it was allowed but did not take effect (invalid input,
	// conflict, storage error).
	OutcomeFailure = "failure"
)

// Event is one audit record.
type Event struct {
	// ID is assigned by the store; zero until stored.
	ID   int64     `json:"id,omitempty"`
	Time time.Time `json:"time"`
	// RequestID joins the record with the registry's and the PDP's logs.
	RequestID string   `json:"requestId,omitempty"`
	Actor     Actor    `json:"actor"`
	Action    string   `json:"action"`
	Resource  Resource `json:"resource"`
	Outcome   string   `json:"outcome"`
	// Detail is the result (created, configured, unchanged, deleted) or why
	// it was denied or failed. It never holds resource contents.
	Detail string `json:"detail,omitempty"`
	// Source names what submitted the change, such as an importer; empty for
	// the API.
	Source string `json:"source,omitempty"`
}

// Actor identifies the caller. Every field is empty for an anonymous caller.
type Actor struct {
	Subject  string `json:"subject,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Username string `json:"username,omitempty"`
	// Client is true for a client acting for itself (client credentials).
	Client bool `json:"client,omitempty"`
	// Via lists the subjects acting on the caller's behalf (the token's
	// "act" chain), outermost first.
	Via []string `json:"via,omitempty"`
}

// Resource is what the action applied to.
type Resource struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Tag       string `json:"tag,omitempty"`
}

// Recorder receives audit events. Implementations must be safe for
// concurrent use and must not fail the caller's operation: an event that
// cannot be kept is logged.
type Recorder interface {
	Record(ctx context.Context, e Event)
}

// RecorderFunc adapts a function to Recorder.
type RecorderFunc func(ctx context.Context, e Event)

// Record calls f.
func (f RecorderFunc) Record(ctx context.Context, e Event) { f(ctx, e) }

// Record annotates e from ctx and passes it to r. It does nothing when r is
// nil or the operation is the registry's own (a system session), so callers
// can record unconditionally.
func Record(ctx context.Context, r Recorder, e Event) {
	if r == nil {
		return
	}
	if s, ok := auth.AuthSessionFrom(ctx); ok && auth.IsSystemSession(s) {
		return
	}
	r.Record(ctx, Annotate(ctx, e))
}

// Annotate fills the time, request ID and actor of e from ctx where e leaves
// them empty.
func Annotate(ctx context.Context, e Event) Event {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.RequestID == "" {
		e.RequestID = authzen.RequestIDFrom(ctx)
	}
	if e.Actor.Subject == "" {
		e.Actor = ActorFrom(ctx)
	}
	return e
}

// ActorFrom returns the caller of ctx's session.
func ActorFrom(ctx context.Context) Actor {
	s, ok := auth.AuthSessionFrom(ctx)
	if !ok || s == nil {
		return Actor{}
	}
	p := s.Principal()
	a := Actor{Subject: p.Subject, Issuer: p.Issuer, Username: p.Username, Client: p.IsClient}
	for _, act := range p.Actor {
		a.Via = append(a.Via, act.Subject)
	}
	return a
}

// Multi returns a Recorder that passes each event to every non-nil recorder.
func Multi(recorders ...Recorder) Recorder {
	var out multi
	for _, r := range recorders {
		if r != nil {
			out = append(out, r)
		}
	}
	switch len(out) {
	case 0:
		return nil
	case 1:
		return out[0]
	}
	return out
}

type multi []Recorder

func (m multi) Record(ctx context.Context, e Event) {
	for _, r := range m {
		r.Record(ctx, e)
	}
}

// Store keeps events.
type Store interface {
	InsertAuditEvent(ctx context.Context, e Event) (int64, error)
}

// StoreRecorder returns a Recorder that writes each event to store. A write
// that fails is logged with the event, and the operation is not failed.
func StoreRecorder(store Store, log *slog.Logger) Recorder {
	return RecorderFunc(func(ctx context.Context, e Event) {
		// Keep the record even when the request was cancelled after the
		// operation took effect.
		if _, err := store.InsertAuditEvent(context.WithoutCancel(ctx), e); err != nil {
			log.ErrorContext(ctx, "audit event not stored", "error", err,
				"action", e.Action, "kind", e.Resource.Kind, "namespace", e.Resource.Namespace,
				"name", e.Resource.Name, "outcome", e.Outcome, "subject", e.Actor.Subject,
				"request_id", e.RequestID)
		}
	})
}

// ErrInvalidCursor is returned for a page cursor the store did not issue.
var ErrInvalidCursor = errors.New("invalid audit cursor")

// Query selects events. Empty fields match everything.
type Query struct {
	// Actor matches the subject or the username exactly.
	Actor     string
	Action    string
	Outcome   string
	Kind      string
	Namespace string
	Name      string
	Since     time.Time
	Until     time.Time
	// Limit caps the events returned (default 50, at most 500).
	Limit int
	// Cursor continues a previous page.
	Cursor string
}

// Lister reads events back, newest first.
type Lister interface {
	ListAuditEvents(ctx context.Context, q Query) (events []Event, nextCursor string, err error)
}
