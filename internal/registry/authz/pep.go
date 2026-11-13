// Package authz is the registry's Policy Enforcement Point. It turns
// resource handler hooks and auth.AuthzProvider calls into OpenID AuthZEN
// 1.0 requests as fixed by docs/auth/authzen-contract.md.
package authz

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

// PEPName is sent as context.pep.
const PEPName = "agentregistry"

const defaultListMax = 1000

var logger = logging.New("authz")

// Decider is the subset of *authzen.Client the PEP uses.
type Decider interface {
	Evaluate(ctx context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error)
	Evaluations(ctx context.Context, req authzen.EvaluationsRequest) (authzen.EvaluationsResponse, error)
	SupportsResourceSearch(ctx context.Context) (bool, error)
	SearchResources(ctx context.Context, req authzen.ResourceSearchRequest, max int) ([]authzen.Resource, error)
}

var _ Decider = (*authzen.Client)(nil)

// Config configures the PEP.
type Config struct {
	// Client asks the PDP. Required.
	Client Decider
	// Lister supplies list candidates when the PDP has no Resource Search.
	// Without it such lists fail with 503.
	Lister CandidateLister
	// ListMax caps the candidate rows authorized per list (default 1000).
	ListMax int
	// SearchMax caps Resource Search results per list (default ListMax).
	// Results beyond it fail the list with 503.
	SearchMax int
	// ExtraKinds adds extension kinds to Authorizers and ListFilters.
	ExtraKinds []string
	// Logger overrides the package logger.
	Logger *slog.Logger
	// Audit records refused reads and lists. Nil records nothing.
	Audit audit.Recorder
}

// PEP enforces PDP decisions. It is safe for concurrent use.
type PEP struct {
	client    Decider
	lister    CandidateLister
	listMax   int
	searchMax int
	kinds     []string
	log       *slog.Logger
	audit     audit.Recorder

	// missingIdentity logs the first session refused for lacking an identity.
	missingIdentity sync.Once
}

var _ auth.AuthzProvider = (*PEP)(nil)

// New returns a PEP. Wire its Authorizers, ListFilters and (as
// auth.AuthzProvider) the PEP itself.
func New(cfg Config) (*PEP, error) {
	if cfg.Client == nil {
		return nil, errors.New("authz: a PDP client is required")
	}
	p := &PEP{
		client:    cfg.Client,
		lister:    cfg.Lister,
		listMax:   cfg.ListMax,
		searchMax: cfg.SearchMax,
		kinds:     append(append([]string{}, BuiltinKinds...), cfg.ExtraKinds...),
		log:       cfg.Logger,
		audit:     cfg.Audit,
	}
	if p.listMax <= 0 {
		p.listMax = defaultListMax
	}
	if p.searchMax <= 0 {
		p.searchMax = p.listMax
	}
	if p.log == nil {
		p.log = logger
	}
	return p, nil
}

// evaluate asks for one decision and logs it. A PDP failure is a 503; a
// denial returns (false, nil) so the caller picks 403 or 404.
func (p *PEP) evaluate(ctx context.Context, subject authzen.Subject, action string, res authzen.Resource) (bool, error) {
	resp, _, err := p.decide(ctx, subject, action, res, requestContext(ctx))
	return resp.Decision, err
}

// decide is evaluate with the request context given, returning the full
// response and the request sent, for denials that may be approved.
func (p *PEP) decide(ctx context.Context, subject authzen.Subject, action string, res authzen.Resource, reqCtx authzen.Context) (authzen.EvaluationResponse, authzen.EvaluationRequest, error) {
	req := authzen.EvaluationRequest{
		Subject:  subject,
		Action:   authzen.Action{Name: action},
		Resource: res,
		Context:  reqCtx,
	}
	resp, err := p.client.Evaluate(ctx, req)
	if err != nil {
		p.logError(ctx, subject, action, res, err)
		return authzen.EvaluationResponse{}, req, unavailable(err)
	}
	p.logDecision(ctx, subject, action, res, resp.Decision)
	return resp, req, nil
}

func (p *PEP) logDecision(ctx context.Context, subject authzen.Subject, action string, res authzen.Resource, permit bool) {
	attrs := []any{
		"subject_type", subject.Type, "subject_id", subject.ID,
		"action", action, "resource_type", res.Type, "resource_id", res.ID,
		"request_id", authzen.RequestIDFrom(ctx), "decision", permit,
	}
	p.log.DebugContext(ctx, "authz decision", attrs...)
	if !permit {
		p.log.InfoContext(ctx, "authz denied", attrs...)
	}
}

func (p *PEP) logError(ctx context.Context, subject authzen.Subject, action string, res authzen.Resource, err error) {
	p.log.WarnContext(ctx, "authz decision failed",
		"subject_type", subject.Type, "subject_id", subject.ID,
		"action", action, "resource_type", res.Type, "resource_id", res.ID,
		"request_id", authzen.RequestIDFrom(ctx), "error", err)
}
