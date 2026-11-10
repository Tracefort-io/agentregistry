package jwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

// maxActorDepth bounds the RFC 8693 "act" chain read from a token.
const maxActorDepth = 16

// Session is the session of a caller authenticated with a JWT.
type Session struct {
	principal auth.Principal
}

var _ auth.Session = (*Session)(nil)

// Principal returns the authenticated caller.
func (s *Session) Principal() auth.Principal {
	return s.principal
}

// newSession builds the session from verified claims.
func newSession(cfg *IssuerConfig, claims map[string]any) (*Session, error) {
	subject, _ := claims[cfg.SubjectClaim].(string)
	if subject == "" {
		return nil, fmt.Errorf("%w: missing subject claim %q", auth.ErrUnauthenticated, cfg.SubjectClaim)
	}
	actors, err := parseActors(claims["act"])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", auth.ErrUnauthenticated, err)
	}
	p := auth.Principal{
		Subject:  subject,
		Issuer:   cfg.Issuer,
		ClientID: firstString(claims, cfg.clientIDClaims()),
		Username: firstString(claims, cfg.usernameClaims()),
		Roles:    stringsAt(claims, cfg.RolesClaim),
		Groups:   stringsAt(claims, cfg.GroupsClaim),
		Actor:    actors,
		Claims:   claims,
	}
	// A client acting for itself: the issuer's clientSubjectClaim decides when
	// configured, otherwise a subject equal to the client ID.
	p.IsClient = p.ClientID != "" && p.Subject == p.ClientID
	if cfg.ClientSubjectClaim != "" {
		p.IsClient = truthy(lookupPath(claims, cfg.ClientSubjectClaim))
	}
	return &Session{principal: p}, nil
}

// parseActors flattens a nested RFC 8693 "act" claim, outermost (current)
// actor first.
func parseActors(v any) ([]auth.Actor, error) {
	var actors []auth.Actor
	for v != nil {
		if len(actors) == maxActorDepth {
			return nil, errors.New("act claim is nested too deeply")
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("act claim is not an object")
		}
		sub, _ := m["sub"].(string)
		if sub == "" {
			return nil, errors.New("act claim has no subject")
		}
		iss, _ := m["iss"].(string)
		actors = append(actors, auth.Actor{Subject: sub, Issuer: iss})
		v = m["act"]
	}
	return actors, nil
}

// firstString returns the first non-empty string claim among names.
func firstString(claims map[string]any, names []string) string {
	for _, name := range names {
		if s, ok := claims[name].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// stringsAt reads a string list at a dotted path. A single string is
// returned as a one-element list; non-string elements are skipped.
func stringsAt(claims map[string]any, path string) []string {
	switch v := lookupPath(claims, path).(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// lookupPath resolves a dotted path through nested objects. Keys may
// themselves contain dots (Keycloak client IDs in
// "resource_access.<client>.roles"): at each level an exact match on the
// remaining path wins, then every split point is tried from left to right.
func lookupPath(m map[string]any, path string) any {
	if path == "" {
		return nil
	}
	if v, ok := m[path]; ok {
		return v
	}
	for i := 0; i < len(path); i++ {
		if path[i] != '.' {
			continue
		}
		child, ok := m[path[:i]].(map[string]any)
		if !ok {
			continue
		}
		if v := lookupPath(child, path[i+1:]); v != nil {
			return v
		}
	}
	return nil
}

// truthy interprets a claim value as a boolean flag.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		switch strings.ToLower(t) {
		case "", "false", "0", "no":
			return false
		}
		return true
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}
