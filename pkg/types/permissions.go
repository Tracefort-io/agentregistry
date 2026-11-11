package types

import (
	"context"
	"slices"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

// Actions a caller can be allowed on a kind. They match the AuthZEN actions
// in docs/auth/authzen-contract.md.
const (
	ActionRead   = "read"
	ActionList   = "list"
	ActionApply  = "apply"
	ActionDelete = "delete"
	ActionDeploy = "deploy"
)

// KindActions lists the actions that apply to a kind: read, list, apply and
// delete for every kind, plus deploy for the kinds a Deployment can target.
func KindActions(kind string) []string {
	actions := []string{ActionRead, ActionList, ActionApply, ActionDelete}
	if kind == v1alpha1.KindAgent || kind == v1alpha1.KindMCPServer {
		actions = append(actions, ActionDeploy)
	}
	return actions
}

// Permissions is what the caller may do in one namespace, for clients such as
// the web UI to show only the actions that will succeed. It is advisory:
// every request is still authorized on its own.
type Permissions struct {
	// Admin is the registry-wide admin check.
	Admin bool
	// Kinds maps each Kind to the actions the caller may take on resources
	// of that kind in the namespace.
	Kinds map[string][]string
}

// Allows reports whether action is permitted on kind.
func (p Permissions) Allows(kind, action string) bool {
	return slices.Contains(p.Kinds[kind], action)
}

// PermissionsFunc resolves the caller's Permissions in a namespace ("" for
// every namespace). The caller's session is in ctx.
type PermissionsFunc func(ctx context.Context, namespace string) (Permissions, error)

// AllPermissions grants every action on kinds, for a registry without
// authorization.
func AllPermissions(kinds []string) Permissions {
	out := Permissions{Admin: true, Kinds: make(map[string][]string, len(kinds))}
	for _, kind := range kinds {
		out.Kinds[kind] = KindActions(kind)
	}
	return out
}
