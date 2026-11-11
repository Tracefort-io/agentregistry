package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

func TestPermissions(t *testing.T) {
	// A reader: read and list on everything except secrets, no admin.
	reader := func(r authzen.EvaluationRequest) bool {
		return (r.Action.Name == "read" || r.Action.Name == "list") && r.Resource.Type != "secret"
	}
	pdp := newMockPDP(reader)
	p := newPEP(t, pdp, nil)

	got, err := p.Permissions(userCtx(alice()), "team")
	require.NoError(t, err)

	assert.False(t, got.Admin)
	assert.Equal(t, []string{"read", "list"}, got.Kinds[v1alpha1.KindAgent])
	assert.Equal(t, []string{}, got.Kinds[v1alpha1.KindSecret], "every covered kind is listed, even with no actions")
	assert.Len(t, got.Kinds, len(BuiltinKinds))

	// One execute_all batch: admin first, then each kind's actions on its
	// collection in the namespace.
	require.Len(t, pdp.batches, 1)
	b := pdp.batches[0]
	assert.Equal(t, authzen.ExecuteAll, b.Semantic())
	assert.Equal(t, "alice-sub", b.Subject.ID)
	assert.Equal(t, "admin", b.Evaluations[0].Action.Name)
	assert.Equal(t, authzen.Resource{Type: "registry", ID: "agentregistry"}, *b.Evaluations[0].Resource)
	assert.Equal(t, "team/*", b.Evaluations[1].Resource.ID)
	assert.Empty(t, pdp.evals)
}

func TestPermissionsWriterAndAdmin(t *testing.T) {
	pdp := newMockPDP(nil) // permits everything
	p := newPEP(t, pdp, nil)

	got, err := p.Permissions(userCtx(alice()), "")
	require.NoError(t, err)

	assert.True(t, got.Admin)
	assert.Equal(t, types.KindActions(v1alpha1.KindAgent), got.Kinds[v1alpha1.KindAgent])
	assert.Contains(t, got.Kinds[v1alpha1.KindMCPServer], "deploy")
	assert.NotContains(t, got.Kinds[v1alpha1.KindPrompt], "deploy", "only Agents and MCPServers are deployable")
	assert.Equal(t, "*", pdp.batches[0].Evaluations[1].Resource.ID, "every namespace")
}

func TestPermissionsChunksLargeBatches(t *testing.T) {
	extra := make([]string, 30)
	for i := range extra {
		extra[i] = "Widget" + string(rune('A'+i))
	}
	pdp := newMockPDP(nil)
	p := newPEP(t, pdp, func(c *Config) { c.ExtraKinds = extra })

	got, err := p.Permissions(userCtx(alice()), "team")
	require.NoError(t, err)

	// 1 admin check + 4-5 actions for each of 39 kinds is more than one batch.
	assert.Greater(t, len(pdp.batches), 1)
	for _, b := range pdp.batches {
		assert.LessOrEqual(t, len(b.Evaluations), evaluationsChunk)
	}
	assert.Equal(t, types.KindActions("WidgetC"), got.Kinds["WidgetC"])
}

func TestPermissionsSessions(t *testing.T) {
	t.Run("system session may do everything", func(t *testing.T) {
		pdp := newMockPDP(nil)
		p := newPEP(t, pdp, nil)
		got, err := p.Permissions(auth.WithSystemContext(context.Background()), "team")
		require.NoError(t, err)
		assert.True(t, got.Admin)
		assert.True(t, got.Allows(v1alpha1.KindAgent, "deploy"))
		assert.Zero(t, pdp.calls())
	})
	t.Run("no session is 401", func(t *testing.T) {
		_, err := newPEP(t, newMockPDP(nil), nil).Permissions(context.Background(), "team")
		assert.Equal(t, 401, StatusOf(err))
	})
	t.Run("pdp failure is 503", func(t *testing.T) {
		pdp := newMockPDP(nil)
		pdp.err = errPDPDown
		_, err := newPEP(t, pdp, nil).Permissions(userCtx(alice()), "team")
		assert.Equal(t, 503, StatusOf(err))
	})
	t.Run("short batch is 503", func(t *testing.T) {
		pdp := newMockPDP(nil)
		pdp.shortBy = 1
		_, err := newPEP(t, pdp, nil).Permissions(userCtx(alice()), "team")
		assert.Equal(t, 503, StatusOf(err))
	})
}
