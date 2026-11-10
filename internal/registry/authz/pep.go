// Package authz is the registry's Policy Enforcement Point. It turns
// resource handler hooks and auth.AuthzProvider calls into OpenID AuthZEN
// 1.0 requests as fixed by docs/auth/authzen-contract.md.
package authz

import (
	"context"
	"errors"
	"log/slog"

	"github.com/agentregistry-dev/agentregistry/pkg/logging"
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
	// SearchMax caps Resource Search results per list; 0 is unbounded.
	SearchMax int
	// ExtraKinds adds extension kinds to Authorizers and ListFilters.
	ExtraKinds []string
	// IsClient decides subject type "client"; nil uses IsClientToken.
	IsClient func(auth.Principal) bool
	// Logger overrides the package logger.
	Logger *slog.Logger
}

// PEP enforces PDP decisions. It is safe for concurrent use.
type PEP struct {
	client    Decider
	lister    CandidateLister
	listMax   int
	searchMax int
	kinds     []string
	isClient  func(auth.Principal) bool
	log       *slog.Logger
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
		isClient:  cfg.IsClient,
		log:       cfg.Logger,
	}
	if p.listMax <= 0 {
		p.listMax = defaultListMax
	}
	if p.isClient == nil {
		p.isClient = IsClientToken
	}
	if p.log == nil {
		p.log = logger
	}
	return p, nil
}

// evaluate asks for one decision and logs it. A PDP failure is a 503; a
// denial returns (false, nil) so the caller picks 403 or 404.
func (p *PEP) evaluate(ctx context.Context, subject authzen.Subject, action string, res authzen.Resource) (bool, error) {
	resp, err := p.client.Evaluate(ctx, authzen.EvaluationRequest{
		Subject:  subject,
		Action:   authzen.Action{Name: action},
		Resource: res,
		Context:  requestContext(ctx),
	})
	if err != nil {
		p.logError(ctx, subject, action, res, err)
		return false, unavailable(err)
	}
	p.logDecision(ctx, subject, action, res, resp.Decision)
	return resp.Decision, nil
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
