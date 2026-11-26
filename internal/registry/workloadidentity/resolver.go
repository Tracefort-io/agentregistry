package workloadidentity

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/agentregistry-dev/agentregistry/internal/registry/tracing"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

// Reasons an ID does not resolve. Every one of them rejects the request.
var (
	// ErrMissing: the gateway sent no token subject or no certificate ID.
	ErrMissing = errors.New("identity proof missing")
	// ErrMismatch: the JWT-SVID and the X.509-SVID name different IDs.
	ErrMismatch = errors.New("JWT-SVID and X.509-SVID name different SPIFFE IDs")
	// ErrUnknown: the registry never assigned the ID's prefix.
	ErrUnknown = errors.New("identity was never assigned")
	// ErrRevoked: the registry revoked the ID's prefix; it is never valid again.
	ErrRevoked = errors.New("identity was revoked")
	// ErrRecordMismatch: the ID's org, agent or Deployment UID differ from
	// the assignment of its prefix.
	ErrRecordMismatch = errors.New("identity does not match its assignment")
)

// HistoryFunc returns the identity events of a SPIFFE ID prefix, oldest first
// (v1alpha1store.Store.IdentityHistory of the Deployment store).
type HistoryFunc func(ctx context.Context, prefix string) ([]v1alpha1store.IdentityEvent, error)

// Resolution is the registered workload a verified SPIFFE ID belongs to.
type Resolution struct {
	SPIFFEID            string
	AgentNamespace      string
	AgentName           string
	AgentTag            string
	DeploymentNamespace string
	DeploymentName      string
	DeploymentUID       string
}

// Resolver resolves verified agent workload SPIFFE IDs. It keeps no cache:
// every call reads the current records, so a revocation applies at once.
type Resolver struct {
	trustDomain string
	history     HistoryFunc
}

// NewResolver returns a Resolver for IDs in trustDomain.
func NewResolver(trustDomain string, history HistoryFunc) (*Resolver, error) {
	if trustDomain == "" || history == nil {
		return nil, errors.New("workload identity: a trust domain and an identity history are required")
	}
	return &Resolver{trustDomain: trustDomain, history: history}, nil
}

// Resolve resolves the SPIFFE ID that the gateway verified twice: as the
// subject of the agent's JWT-SVID and as the ID in its X.509-SVID (the TLS
// client certificate). Both must name the same ID, of an agent workload in
// the trust domain, whose prefix the registry assigned to a Deployment and
// never revoked, with the org, agent and Deployment UID of that assignment.
// A rejection wraps one of the Err* reasons; any other error means the
// records could not be read.
func (r *Resolver) Resolve(ctx context.Context, tokenSubject, certificateID string) (res Resolution, err error) {
	ctx, span := tracing.Tracer().Start(ctx, "identity.resolve",
		trace.WithAttributes(attribute.String("spiffe.id", tokenSubject)))
	defer func() {
		span.SetAttributes(attribute.String("identity.outcome", outcome(err)))
		if err == nil {
			span.SetAttributes(
				attribute.String("agentregistry.agent", res.AgentNamespace+"/"+res.AgentName+":"+res.AgentTag),
				attribute.String("agentregistry.deployment", res.DeploymentNamespace+"/"+res.DeploymentName),
			)
		} else if !Rejected(err) {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	return r.resolve(ctx, tokenSubject, certificateID)
}

// outcome names a resolution's result for traces: resolved, the rejection
// reason, or error when the records could not be read.
func outcome(err error) string {
	for reason, name := range map[error]string{
		ErrMissing: "missing", ErrMismatch: "mismatch", ErrMalformed: "malformed", ErrUnknown: "unknown",
		ErrRevoked: "revoked", ErrRecordMismatch: "record_mismatch",
	} {
		if errors.Is(err, reason) {
			return name
		}
	}
	if err == nil {
		return "resolved"
	}
	return "error"
}

func (r *Resolver) resolve(ctx context.Context, tokenSubject, certificateID string) (Resolution, error) {
	if tokenSubject == "" || certificateID == "" {
		return Resolution{}, ErrMissing
	}
	if tokenSubject != certificateID {
		return Resolution{}, ErrMismatch
	}
	id, err := ParseAgentID(tokenSubject, r.trustDomain)
	if err != nil {
		return Resolution{}, err
	}
	hctx, hspan := tracing.Tracer().Start(ctx, "identity.history",
		trace.WithAttributes(attribute.String("spiffe.id.prefix", id.Prefix())))
	events, err := r.history(hctx, id.Prefix())
	hspan.SetAttributes(attribute.Int("identity.events", len(events)))
	if err != nil {
		hspan.SetStatus(codes.Error, err.Error())
	}
	hspan.End()
	if err != nil {
		return Resolution{}, fmt.Errorf("read identity records: %w", err)
	}
	var assigned *v1alpha1store.IdentityEvent
	for i := range events {
		switch events[i].Event {
		case v1alpha1store.IdentityRevoked:
			return Resolution{}, ErrRevoked
		case v1alpha1store.IdentityAssigned:
			assigned = &events[i]
		}
	}
	if assigned == nil {
		return Resolution{}, ErrUnknown
	}
	// The org is the Deployment's registry namespace (the KubernetesWorkload
	// runtime builds the ID from it).
	if assigned.DeploymentNamespace != id.Org || assigned.AgentName != id.Agent || assigned.DeploymentUID != id.DeploymentUID {
		return Resolution{}, ErrRecordMismatch
	}
	return Resolution{
		SPIFFEID:            id.String(),
		AgentNamespace:      assigned.AgentNamespace,
		AgentName:           assigned.AgentName,
		AgentTag:            assigned.AgentTag,
		DeploymentNamespace: assigned.DeploymentNamespace,
		DeploymentName:      assigned.DeploymentName,
		DeploymentUID:       assigned.DeploymentUID,
	}, nil
}

// Rejected reports whether err is a rejection of the ID, as opposed to a
// failure to read the records.
func Rejected(err error) bool {
	for _, reason := range []error{ErrMissing, ErrMismatch, ErrMalformed, ErrUnknown, ErrRevoked, ErrRecordMismatch} {
		if errors.Is(err, reason) {
			return true
		}
	}
	return false
}
