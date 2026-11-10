package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

// Subject types sent to the PDP.
const (
	SubjectTypeUser      = "user"
	SubjectTypeClient    = "client"
	SubjectTypeAnonymous = "anonymous"
)

// caller is the resolved identity of a request.
type caller struct {
	// system bypasses the PDP for internal reconciliation.
	system  bool
	subject authzen.Subject
}

// callerFrom resolves the session in ctx. A missing session or an
// unauthenticated principal is a 401.
func (p *PEP) callerFrom(ctx context.Context) (caller, error) {
	s, ok := auth.AuthSessionFrom(ctx)
	if !ok {
		return caller{}, unauthenticated()
	}
	return p.callerFor(s)
}

func (p *PEP) callerFor(s auth.Session) (caller, error) {
	switch {
	case s == nil:
		return caller{}, unauthenticated()
	case auth.IsSystemSession(s):
		return caller{system: true}, nil
	case auth.IsPublicSession(s):
		return caller{subject: authzen.Subject{Type: SubjectTypeAnonymous, ID: "anonymous"}}, nil
	}
	pr := s.Principal()
	if !pr.IsAuthenticated() {
		// The session came from an AuthnProvider but carries no identity the
		// PDP can be asked about. Refuse it, and say why once: a custom
		// provider that only fills Principal.User would otherwise fail
		// every request without explanation.
		p.missingIdentity.Do(func() {
			p.log.Warn("refusing sessions without Principal.Subject and Principal.Issuer; "+
				"the AuthnProvider must set them when auth mode is required",
				"session_type", fmt.Sprintf("%T", s))
		})
		return caller{}, unauthenticated()
	}
	return caller{subject: subjectFor(pr)}, nil
}

// subjectFor builds the contract's subject from verified claims. The subject
// type follows Principal.IsClient, which the AuthnProvider sets.
func subjectFor(pr auth.Principal) authzen.Subject {
	props := map[string]any{
		"iss":    pr.Issuer,
		"roles":  nonNil(pr.Roles),
		"groups": nonNil(pr.Groups),
	}
	if pr.Username != "" {
		props["username"] = pr.Username
	}
	if pr.ClientID != "" {
		props["client_id"] = pr.ClientID
	}
	if len(pr.Actor) > 0 {
		act := make([]map[string]any, 0, len(pr.Actor))
		for _, a := range pr.Actor {
			act = append(act, map[string]any{"sub": a.Subject, "iss": a.Issuer})
		}
		props["act"] = act
	}
	typ := SubjectTypeUser
	if pr.IsClient {
		typ = SubjectTypeClient
	}
	return authzen.Subject{Type: typ, ID: pr.Subject, Properties: props}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// requestContext is the contract's evaluation context.
func requestContext(ctx context.Context) authzen.Context {
	c := authzen.Context{"pep": PEPName}
	if id := strings.TrimSpace(authzen.RequestIDFrom(ctx)); id != "" {
		c["request_id"] = id
	}
	return c
}
