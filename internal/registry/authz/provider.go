package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

// registryResource is the target of the registry-wide admin check.
var registryResource = authzen.Resource{Type: "registry", ID: PEPName}

// permissionAction maps an auth.PermissionAction to a contract action.
func permissionAction(a auth.PermissionAction) (string, bool) {
	switch a {
	case auth.PermissionActionRead:
		return ActionRead, true
	case auth.PermissionActionPublish, auth.PermissionActionEdit:
		return ActionApply, true
	case auth.PermissionActionDelete:
		return ActionDelete, true
	case auth.PermissionActionDeploy:
		return ActionDeploy, true
	default:
		return "", false
	}
}

// permissionResource maps an auth.Resource to a contract resource. The
// legacy "server" type is the MCPServer kind; Name is used as the id.
func permissionResource(r auth.Resource) authzen.Resource {
	typ := strings.ToLower(string(r.Type))
	if r.Type == auth.PermissionArtifactTypeServer {
		typ = "mcpserver"
	}
	props := map[string]any{"name": r.Name}
	if ns, name, ok := strings.Cut(r.Name, "/"); ok {
		props["namespace"], props["name"] = ns, name
	}
	return authzen.Resource{Type: typ, ID: r.Name, Properties: props}
}

// Check implements auth.AuthzProvider for single-resource operations.
// Denials are 403 errors matching auth.ErrForbidden; PDP failures are 503.
func (p *PEP) Check(ctx context.Context, s auth.Session, verb auth.PermissionAction, resource auth.Resource) error {
	c, err := p.callerFor(s)
	if err != nil {
		return err
	}
	if c.system {
		return nil
	}
	action, ok := permissionAction(verb)
	if !ok {
		return forbidden(fmt.Sprintf("unsupported permission %q", verb))
	}
	res := permissionResource(resource)
	permit, err := p.evaluate(ctx, c.subject, action, res)
	if err != nil {
		return err
	}
	if !permit {
		return forbidden(fmt.Sprintf("not permitted to %s %s %s", action, res.Type, res.ID))
	}
	return nil
}

// IsRegistryAdmin implements auth.AuthzProvider with action "admin" on the
// registry resource. It fails closed: any error is false.
func (p *PEP) IsRegistryAdmin(ctx context.Context, s auth.Session) bool {
	c, err := p.callerFor(s)
	if err != nil {
		return false
	}
	if c.system {
		return true
	}
	permit, err := p.evaluate(ctx, c.subject, ActionAdmin, registryResource)
	return err == nil && permit
}
