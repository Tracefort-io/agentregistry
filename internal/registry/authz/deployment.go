package authz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// authorizeDeploymentApply sends one deny_on_first_deny batch: deploy on
// the target, read on the runtime, apply on the Deployment, then read on
// every other resource the Deployment binds to (its effective Model and its
// deploymentRefs). All must permit. The refs come from the submitted
// Deployment.
func (p *PEP) authorizeDeploymentApply(ctx context.Context, subject authzen.Subject, in types.AuthorizeInput) error {
	spec, err := deploymentSpec(in.Object)
	if err != nil {
		p.log.InfoContext(ctx, "authz denied deployment without readable spec",
			"subject_id", subject.ID, "resource_id", in.Namespace+"/"+in.Name,
			"request_id", authzen.RequestIDFrom(ctx), "error", err)
		return forbidden("deployment apply requires a Deployment with spec.targetRef and spec.runtimeRef")
	}
	target := spec.TargetRef
	if (target.Kind != v1alpha1.KindAgent && target.Kind != v1alpha1.KindMCPServer) || target.Name == "" {
		return forbidden("deployment spec.targetRef must name an Agent or MCPServer")
	}
	runtime := spec.RuntimeRef
	if runtime.Name == "" {
		return forbidden("deployment spec.runtimeRef must name a Runtime")
	}

	type check struct {
		action string
		res    authzen.Resource
	}
	checks := []check{
		{ActionDeploy, objectResource(target.Kind, defaultNS(target.Namespace, in.Namespace), target.Name, target.Tag)},
		{ActionRead, objectResource(v1alpha1.KindRuntime, defaultNS(runtime.Namespace, in.Namespace), runtime.Name, "")},
		{ActionApply, objectResource(v1alpha1.KindDeployment, in.Namespace, in.Name, "")},
	}
	if model := spec.EffectiveModelRef(); model != nil {
		checks = append(checks, check{ActionRead,
			objectResource(v1alpha1.KindModel, defaultNS(model.Namespace, in.Namespace), model.Name, model.Tag)})
	}
	for _, ref := range spec.DeploymentRefs {
		checks = append(checks, check{ActionRead,
			objectResource(v1alpha1.KindDeployment, defaultNS(ref.Namespace, in.Namespace), ref.Name, "")})
	}
	req := authzen.EvaluationsRequest{
		Subject:     &subject,
		Context:     requestContext(ctx),
		Options:     &authzen.EvaluationsOptions{EvaluationsSemantic: authzen.DenyOnFirstDeny},
		Evaluations: make([]authzen.EvaluationItem, len(checks)),
	}
	for i := range checks {
		req.Evaluations[i] = authzen.EvaluationItem{
			Action:   &authzen.Action{Name: checks[i].action},
			Resource: &checks[i].res,
		}
	}

	resp, err := p.client.Evaluations(ctx, req)
	if err != nil {
		p.logError(ctx, subject, ActionApply, checks[2].res, err)
		return unavailable(err)
	}
	for i, check := range checks {
		if i >= len(resp.Evaluations) {
			// A short batch without a deny cannot be read as a permit.
			err := fmt.Errorf("deployment batch returned %d of %d decisions", len(resp.Evaluations), len(checks))
			p.logError(ctx, subject, check.action, check.res, err)
			return unavailable(err)
		}
		permit := resp.Evaluations[i].Decision
		p.logDecision(ctx, subject, check.action, check.res, permit)
		if !permit {
			return forbidden(fmt.Sprintf("not permitted to %s %s %s", check.action, check.res.Type, check.res.ID))
		}
	}
	return nil
}

func defaultNS(ns, fallback string) string {
	if ns == "" {
		return fallback
	}
	return ns
}

// deploymentSpec reads the spec from the apply body, accepting the typed
// Deployment or any Object that encodes to one.
func deploymentSpec(obj v1alpha1.Object) (*v1alpha1.DeploymentSpec, error) {
	switch d := obj.(type) {
	case nil:
		return nil, fmt.Errorf("no deployment object")
	case *v1alpha1.Deployment:
		if d == nil {
			return nil, fmt.Errorf("nil deployment object")
		}
		return &d.Spec, nil
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("encode deployment object: %w", err)
	}
	var d v1alpha1.Deployment
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("decode deployment object: %w", err)
	}
	return &d.Spec, nil
}
