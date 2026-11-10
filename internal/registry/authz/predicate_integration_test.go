//go:build integration

package authz

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

// TestPredicate_Postgres runs the list predicate and StoreLister against
// real tagged (Agent) and mutable (Runtime) stores.
func TestPredicate_Postgres(t *testing.T) {
	ctx := context.Background()
	pool := v1alpha1store.NewTestPool(t)
	stores := v1alpha1store.NewStores(pool, v1alpha1store.TestSchemaRegistry())

	agents := stores[v1alpha1.KindAgent]
	for _, a := range []struct{ ns, name, tag string }{
		{"team", "a", "v1"}, {"team", "a", "v2"}, {"team", "b", "v1"},
		{"other", "a", "v1"}, {"team", "x/y", "v1"},
	} {
		_, err := agents.Upsert(ctx, &v1alpha1.Agent{
			Metadata: v1alpha1.ObjectMeta{Namespace: a.ns, Name: a.name, Tag: a.tag},
			Spec:     v1alpha1.AgentSpec{Title: a.name},
		})
		require.NoError(t, err)
	}
	runtimes := stores[v1alpha1.KindRuntime]
	for _, r := range []struct{ ns, name string }{{"team", "k8s"}, {"team", "local"}, {"other", "k8s"}} {
		_, err := runtimes.Upsert(ctx, &v1alpha1.Runtime{
			Metadata: v1alpha1.ObjectMeta{Namespace: r.ns, Name: r.name},
			Spec:     v1alpha1.RuntimeSpec{Type: "Test"},
		})
		require.NoError(t, err)
	}

	keys := func(rows []*v1alpha1.RawObject) []string {
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			k := r.Metadata.Namespace + "/" + r.Metadata.Name
			if r.Metadata.Tag != "" {
				k += "@" + r.Metadata.Tag
			}
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	list := func(store *v1alpha1store.Store, ns string, ids []ResourceID) []string {
		where, args := Predicate(ids)
		rows, _, err := store.List(ctx, v1alpha1store.ListOpts{Namespace: ns, ExtraWhere: where, ExtraArgs: args})
		require.NoError(t, err)
		return keys(rows)
	}

	assert.Equal(t, []string{"other/a@v1", "team/a@v1", "team/a@v2", "team/x/y@v1"},
		list(agents, "", []ResourceID{{"team", "a"}, {"other", "a"}, {"team", "x/y"}, {"nowhere", "z"}}))
	assert.Equal(t, []string{"team/a@v1", "team/a@v2"},
		list(agents, "team", []ResourceID{{"team", "a"}, {"other", "a"}}))
	assert.Empty(t, list(agents, "", nil), "empty set matches nothing")
	assert.Equal(t, []string{"team/k8s"},
		list(runtimes, "", []ResourceID{{"team", "k8s"}}))

	lister := NewStoreLister(stores)
	ids, err := lister.ListIDs(ctx, v1alpha1.KindAgent, "", 0)
	require.NoError(t, err)
	assert.ElementsMatch(t, []ResourceID{{"team", "a"}, {"team", "b"}, {"other", "a"}, {"team", "x/y"}}, ids,
		"tags collapse to one id per name")
	ids, err = lister.ListIDs(ctx, v1alpha1.KindRuntime, "team", 0)
	require.NoError(t, err)
	assert.ElementsMatch(t, []ResourceID{{"team", "k8s"}, {"team", "local"}}, ids)
	ids, err = lister.ListIDs(ctx, v1alpha1.KindAgent, "", 2)
	require.NoError(t, err)
	assert.Len(t, ids, 2)
	_, err = lister.ListIDs(ctx, "Unknown", "", 0)
	assert.Error(t, err)
}
