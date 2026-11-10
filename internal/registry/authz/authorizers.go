package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// Contract action names.
const (
	ActionRead   = "read"
	ActionList   = "list"
	ActionApply  = "apply"
	ActionDelete = "delete"
	ActionDeploy = "deploy"
	ActionAdmin  = "admin"
)

// BuiltinKinds are the kinds every PEP covers.
var BuiltinKinds = []string{
	v1alpha1.KindAgent,
	v1alpha1.KindMCPServer,
	v1alpha1.KindSkill,
	v1alpha1.KindPrompt,
	v1alpha1.KindPlugin,
	v1alpha1.KindModel,
	v1alpha1.KindRuntime,
	v1alpha1.KindDeployment,
	v1alpha1.KindSecret,
}

// actionFor maps a resource handler verb to a contract action.
func actionFor(verb string) (string, bool) {
	switch verb {
	case "get":
		return ActionRead, true
	case "list":
		return ActionList, true
	case "apply":
		return ActionApply, true
	case "delete":
		return ActionDelete, true
	default:
		return "", false
	}
}

// resourceType is the contract's resource type for a Kind.
func resourceType(kind string) string {
	return strings.ToLower(kind)
}

// objectResource is a single resource: id "<namespace>/<name>", with the
// tag in properties when a tagged kind's operation names one.
func objectResource(kind, namespace, name, tag string) authzen.Resource {
	props := map[string]any{"kind": kind, "namespace": namespace, "name": name}
	if tag != "" && v1alpha1.IsTaggedArtifactKind(kind) {
		props["tag"] = tag
	}
	return authzen.Resource{Type: resourceType(kind), ID: namespace + "/" + name, Properties: props}
}

// listResource is a kind's collection: id "<namespace>/*", or "*" across
// all namespaces.
func listResource(kind, namespace string) authzen.Resource {
	props := map[string]any{"kind": kind}
	id := "*"
	if namespace != "" {
		id = namespace + "/*"
		props["namespace"] = namespace
	}
	return authzen.Resource{Type: resourceType(kind), ID: id, Properties: props}
}

// Authorizers returns one hook per covered kind. The apply batch endpoint
// denies kinds without a hook once any are wired, so every kind the
// registry serves must be covered (add extension kinds via
// Config.ExtraKinds).
func (p *PEP) Authorizers() map[string]types.Authorizer {
	out := make(map[string]types.Authorizer, len(p.kinds))
	for _, kind := range p.kinds {
		out[kind] = p.Authorize
	}
	return out
}

// Authorize gates one resource handler call.
//
//   - no or unauthenticated session: 401
//   - SystemSession: allowed without asking the PDP
//   - denied get: 404; other denials: 403; PDP failure: 503
func (p *PEP) Authorize(ctx context.Context, in types.AuthorizeInput) error {
	c, err := p.callerFrom(ctx)
	if err != nil {
		return err
	}
	if c.system {
		return nil
	}
	action, ok := actionFor(in.Verb)
	if !ok {
		p.log.InfoContext(ctx, "authz denied unknown verb", "verb", in.Verb, "kind", in.Kind,
			"subject_id", c.subject.ID, "request_id", authzen.RequestIDFrom(ctx))
		return forbidden(fmt.Sprintf("unsupported operation %q", in.Verb))
	}
	if in.Kind == v1alpha1.KindDeployment && action == ActionApply {
		return p.authorizeDeploymentApply(ctx, c.subject, in)
	}

	var res authzen.Resource
	if action == ActionList {
		res = listResource(in.Kind, in.Namespace)
	} else {
		res = objectResource(in.Kind, in.Namespace, in.Name, in.Tag)
	}
	permit, err := p.evaluate(ctx, c.subject, action, res)
	if err != nil {
		return err
	}
	if permit {
		return nil
	}
	if action == ActionRead {
		return notFound(notFoundDetail(in))
	}
	return forbidden(fmt.Sprintf("not permitted to %s %s %s", action, res.Type, res.ID))
}

// notFoundDetail matches the resource handler's own not-found message.
func notFoundDetail(in types.AuthorizeInput) string {
	if in.Tag == "" {
		return fmt.Sprintf("%s %q/%q not found", in.Kind, in.Namespace, in.Name)
	}
	return fmt.Sprintf("%s %q/%q@%q not found", in.Kind, in.Namespace, in.Name, in.Tag)
}
