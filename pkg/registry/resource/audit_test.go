//go:build integration

package resource_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/resource"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

type auditCollector struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *auditCollector) Record(_ context.Context, e audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *auditCollector) take() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.events
	c.events = nil
	return out
}

func agentDoc(name, tag string) string {
	doc := "apiVersion: ar.dev/v1alpha1\nkind: Agent\nmetadata:\n  namespace: default\n  name: " + name + "\n"
	if tag != "" {
		doc += "  tag: " + tag + "\n"
	}
	return doc + "spec:\n  title: T\n"
}

func TestAudit_RecordsEveryApplyAndDelete(t *testing.T) {
	pool := v1alpha1store.NewTestPool(t)
	store := v1alpha1store.NewStore(pool, v1alpha1store.TestSchema(), "agents")
	rec := &auditCollector{}
	deny := func(_ context.Context, in resource.AuthorizeInput) error {
		if in.Name == "blocked" {
			return auth.ErrForbidden
		}
		return nil
	}

	_, api := humatest.New(t)
	resource.Register[*v1alpha1.Agent](api, resource.Config{
		Kind: v1alpha1.KindAgent, BasePrefix: "/v0", Store: store, Authorize: deny, Audit: rec,
	}, func() *v1alpha1.Agent { return &v1alpha1.Agent{} })
	resource.RegisterApply(api, resource.ApplyConfig{
		BasePrefix:  "/v0",
		Stores:      map[string]*v1alpha1store.Store{v1alpha1.KindAgent: store},
		Authorizers: map[string]func(context.Context, resource.AuthorizeInput) error{v1alpha1.KindAgent: deny},
		Audit:       rec,
	})
	post := func(method, body string) {
		t.Helper()
		resp := api.Do(method, "/v0/apply", "Content-Type: application/yaml", strings.NewReader(body))
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	}

	// One batch: created, denied, invalid.
	post(http.MethodPost, agentDoc("alice", "")+"---\n"+agentDoc("blocked", "")+"---\n"+agentDoc("Bad_Name", ""))
	got := rec.take()
	require.Len(t, got, 3)
	assert.Equal(t, audit.Event{Action: audit.ActionApply, Outcome: audit.OutcomeSuccess, Detail: "created",
		Resource: audit.Resource{Kind: "Agent", Namespace: "default", Name: "alice", Tag: "latest"}}, stripAnnotations(got[0]))
	assert.Equal(t, audit.OutcomeDenied, got[1].Outcome)
	assert.Equal(t, "blocked", got[1].Resource.Name)
	assert.Contains(t, got[1].Detail, "forbidden")
	assert.Equal(t, audit.OutcomeFailure, got[2].Outcome)
	assert.True(t, strings.HasPrefix(got[2].Detail, "validation"), got[2].Detail)
	for _, e := range got {
		assert.False(t, e.Time.IsZero(), "annotated with the time")
	}

	// Re-applying records "unchanged".
	post(http.MethodPost, agentDoc("alice", ""))
	got = rec.take()
	require.Len(t, got, 1)
	assert.Equal(t, "unchanged", got[0].Detail)

	// A dry run changes nothing and records nothing.
	resp := api.Post("/v0/apply?dryRun=true", "Content-Type: application/yaml", strings.NewReader(agentDoc("dave", "")))
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Empty(t, rec.take())

	// Batch delete and single-resource delete.
	post(http.MethodDelete, agentDoc("alice", "latest"))
	got = rec.take()
	require.Len(t, got, 1)
	assert.Equal(t, audit.ActionDelete, got[0].Action)
	assert.Equal(t, audit.OutcomeSuccess, got[0].Outcome)
	assert.Equal(t, "deleted", got[0].Detail)

	// The test authorizer returns a bare ErrForbidden, which this handler
	// maps to 500; the registry's PEP returns a 403 error. Either way the
	// delete is refused and recorded.
	resp = api.Delete("/v0/agents/blocked/latest")
	require.NotEqual(t, http.StatusNoContent, resp.Code, resp.Body.String())
	got = rec.take()
	require.Len(t, got, 1)
	assert.Equal(t, audit.ActionDelete, got[0].Action)
	assert.Equal(t, audit.OutcomeDenied, got[0].Outcome)
}

// The registry's own writes (controllers, reconciliation) are not recorded.
func TestAudit_SkipsSystemSession(t *testing.T) {
	pool := v1alpha1store.NewTestPool(t)
	store := v1alpha1store.NewStore(pool, v1alpha1store.TestSchema(), "agents")
	rec := &auditCollector{}
	obj := &v1alpha1.Agent{Metadata: v1alpha1.ObjectMeta{Namespace: "default", Name: "sys"}, Spec: v1alpha1.AgentSpec{Title: "T"}}
	obj.SetTypeMeta(v1alpha1.TypeMeta{APIVersion: v1alpha1.GroupVersion, Kind: v1alpha1.KindAgent})

	res := resource.ApplyObject(auth.WithSystemContext(t.Context()), resource.ApplyConfig{
		Stores: map[string]*v1alpha1store.Store{v1alpha1.KindAgent: store},
		Audit:  rec,
	}, obj, false)
	require.Empty(t, res.Error)
	assert.Empty(t, rec.take())
}

// stripAnnotations keeps the fields the pipeline sets, dropping the time,
// request ID and actor that audit.Record adds.
func stripAnnotations(e audit.Event) audit.Event {
	return audit.Event{Action: e.Action, Outcome: e.Outcome, Detail: e.Detail, Resource: e.Resource, Source: e.Source}
}
