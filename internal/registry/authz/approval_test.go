package authz

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// requestableDenial is what opa-authzen-plugin returns for a denial the
// policy marks requestable.
func requestableDenial(authzen.EvaluationRequest) map[string]any {
	return map[string]any{
		"reason":        "approval_required",
		"evaluation_id": "eval_1",
		"evaluated_at":  "2026-11-12T09:00:00Z",
		"access_request": map[string]any{
			"template": "registry_change", "expires_at": "2026-11-12T09:10:00Z", "binding_token": "jws.token.sig",
		},
	}
}

func prompt(content string) *v1alpha1.Prompt {
	p := &v1alpha1.Prompt{Metadata: v1alpha1.ObjectMeta{Namespace: "team", Name: "p"}, Spec: v1alpha1.PromptSpec{Content: content}}
	p.SetTypeMeta(v1alpha1.TypeMeta{APIVersion: v1alpha1.GroupVersion, Kind: v1alpha1.KindPrompt})
	return p
}

func TestAuthorize_ApprovalRequired(t *testing.T) {
	deny := func(authzen.EvaluationRequest) bool { return false }
	pdp := newMockPDP(deny)
	pdp.respContext = requestableDenial
	p := newPEP(t, pdp, nil)

	doc := prompt("v1")
	err := p.Authorize(userCtx(alice()), types.AuthorizeInput{Verb: "apply", Kind: v1alpha1.KindPrompt, Namespace: "team", Name: "p", Object: doc})
	var approval *ApprovalRequired
	require.ErrorAs(t, err, &approval)
	assert.Equal(t, http.StatusForbidden, StatusOf(err), "still a 403")
	require.ErrorIs(t, err, auth.ErrForbidden)
	assert.Contains(t, err.Error(), "approval required")

	assert.Equal(t, map[string]any{
		"binding_token": "jws.token.sig", "expires_at": "2026-11-12T09:10:00Z", "template": "registry_change",
		"evaluation_id": "eval_1", "evaluated_at": "2026-11-12T09:00:00Z", "reason": "approval_required",
	}, approval.Denial)

	// The request carries what the access request must match.
	assert.Equal(t, "alice-sub", approval.Request.Subject.ID)
	assert.Equal(t, "apply", approval.Request.Action.Name)
	assert.Equal(t, "team/p", approval.Request.Resource.ID)
	sum, err := DocumentSHA256(doc)
	require.NoError(t, err)
	assert.Equal(t, sum, approval.Request.Context[ContextDocumentSHA256])
}

func TestAuthorize_DocumentHashFollowsContent(t *testing.T) {
	pdp := newMockPDP(nil)
	p := newPEP(t, pdp, nil)
	in := func(obj v1alpha1.Object, kind string) types.AuthorizeInput {
		return types.AuthorizeInput{Verb: "apply", Kind: kind, Namespace: "team", Name: "p", Object: obj}
	}
	require.NoError(t, p.Authorize(userCtx(alice()), in(prompt("v1"), v1alpha1.KindPrompt)))
	require.NoError(t, p.Authorize(userCtx(alice()), in(prompt("v2"), v1alpha1.KindPrompt)))
	require.Len(t, pdp.evals, 2)
	a, b := pdp.evals[0].Context[ContextDocumentSHA256], pdp.evals[1].Context[ContextDocumentSHA256]
	assert.NotEmpty(t, a)
	assert.NotEqual(t, a, b, "different content, different hash")

	secret := &v1alpha1.Secret{Metadata: v1alpha1.ObjectMeta{Namespace: "team", Name: "s"}}
	secret.SetTypeMeta(v1alpha1.TypeMeta{APIVersion: v1alpha1.GroupVersion, Kind: v1alpha1.KindSecret})
	require.NoError(t, p.Authorize(userCtx(alice()), in(secret, v1alpha1.KindSecret)))
	assert.NotContains(t, pdp.evals[2].Context, ContextDocumentSHA256, "no hash derived from Secret values")

	require.NoError(t, p.Authorize(userCtx(alice()), types.AuthorizeInput{Verb: "get", Kind: v1alpha1.KindPrompt, Namespace: "team", Name: "p"}))
	assert.NotContains(t, pdp.evals[3].Context, ContextDocumentSHA256, "reads carry no document")
}

func TestAuthorize_PresentsApproval(t *testing.T) {
	pdp := newMockPDP(nil)
	p := newPEP(t, pdp, nil)
	ctx := types.WithApprovalID(userCtx(alice()), "apr_1")
	require.NoError(t, p.Authorize(ctx, types.AuthorizeInput{Verb: "apply", Kind: v1alpha1.KindPrompt, Namespace: "team", Name: "p", Object: prompt("v1")}))
	assert.Equal(t, map[string]any{"id": "apr_1"}, pdp.evals[0].Context[ContextApproval])
}

func TestAuthorize_PlainDenials(t *testing.T) {
	deny := func(authzen.EvaluationRequest) bool { return false }
	tests := []struct {
		name string
		ctx  func(authzen.EvaluationRequest) map[string]any
		verb string
	}{
		{"no access_request", func(authzen.EvaluationRequest) map[string]any { return map[string]any{"reason": "no"} }, "apply"},
		{"no binding token", func(authzen.EvaluationRequest) map[string]any {
			return map[string]any{"access_request": map[string]any{"template": "t"}}
		}, "apply"},
		{"a read is never requestable", requestableDenial, "get"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newMockPDP(deny)
			pdp.respContext = tt.ctx
			err := newPEP(t, pdp, nil).Authorize(userCtx(alice()), types.AuthorizeInput{Verb: tt.verb, Kind: v1alpha1.KindPrompt, Namespace: "team", Name: "p", Object: prompt("v1")})
			var approval *ApprovalRequired
			assert.NotErrorAs(t, err, &approval)
			require.ErrorIs(t, err, auth.ErrForbidden)
		})
	}
}

func TestAuthorize_DeploymentApprovalRequired(t *testing.T) {
	// The policy allows reads but makes deploying the Agent requestable.
	pdp := newMockPDP(func(r authzen.EvaluationRequest) bool { return r.Action.Name != ActionDeploy })
	pdp.respContext = func(r authzen.EvaluationRequest) map[string]any {
		if r.Action.Name == ActionDeploy {
			return requestableDenial(r)
		}
		return nil
	}
	p := newPEP(t, pdp, nil)
	agentRef := v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: "bot", Tag: "v1"}
	runtimeRef := v1alpha1.ResourceRef{Kind: v1alpha1.KindRuntime, Namespace: "shared", Name: "k8s"}
	err := p.Authorize(userCtx(alice()), types.AuthorizeInput{
		Verb: "apply", Kind: v1alpha1.KindDeployment, Namespace: "team", Name: "d", Object: deployment(agentRef, runtimeRef),
	})
	var approval *ApprovalRequired
	require.ErrorAs(t, err, &approval)
	assert.Equal(t, ActionDeploy, approval.Request.Action.Name)
	assert.Equal(t, "agent", approval.Request.Resource.Type)
	assert.NotEmpty(t, approval.Request.Context[ContextDocumentSHA256], "the batch context reaches the item")
}
