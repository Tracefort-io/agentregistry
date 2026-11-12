//go:build integration

package v1alpha1store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
)

func TestAuditEventStore(t *testing.T) {
	pool := NewTestPool(t)
	store := NewAuditEventStore(pool, TestSchema())
	ctx := context.Background()
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	alice := audit.Actor{Subject: "alice-sub", Issuer: "https://idp", Username: "alice"}
	bob := audit.Actor{Subject: "bob-sub", Issuer: "https://idp", Username: "bob", Via: []string{"agent-1"}}
	events := []audit.Event{
		{Time: base, Actor: alice, Action: audit.ActionApply, Resource: audit.Resource{Kind: "Prompt", Namespace: "default", Name: "p1", Tag: "latest"}, Outcome: audit.OutcomeSuccess, Detail: "created", RequestID: "r1"},
		{Time: base.Add(time.Minute), Actor: bob, Action: audit.ActionApply, Resource: audit.Resource{Kind: "Prompt", Namespace: "default", Name: "p1"}, Outcome: audit.OutcomeDenied, Detail: "not permitted"},
		{Time: base.Add(2 * time.Minute), Actor: bob, Action: audit.ActionRead, Resource: audit.Resource{Kind: "Secret", Namespace: "team", Name: "s1"}, Outcome: audit.OutcomeDenied},
		{Time: base.Add(3 * time.Minute), Actor: alice, Action: audit.ActionDelete, Resource: audit.Resource{Kind: "Prompt", Namespace: "default", Name: "p1"}, Outcome: audit.OutcomeSuccess, Detail: "deleted"},
	}
	for _, e := range events {
		_, err := store.InsertAuditEvent(ctx, e)
		require.NoError(t, err)
	}

	t.Run("round trip, newest first", func(t *testing.T) {
		got, next, err := store.ListAuditEvents(ctx, audit.Query{})
		require.NoError(t, err)
		require.Empty(t, next)
		require.Len(t, got, 4)
		assert.Equal(t, audit.ActionDelete, got[0].Action)
		first := got[3]
		assert.NotZero(t, first.ID)
		assert.True(t, base.Equal(first.Time))
		assert.Equal(t, alice, first.Actor)
		assert.Equal(t, audit.Resource{Kind: "Prompt", Namespace: "default", Name: "p1", Tag: "latest"}, first.Resource)
		assert.Equal(t, "created", first.Detail)
		assert.Equal(t, "r1", first.RequestID)
		assert.Equal(t, []string{"agent-1"}, got[1].Actor.Via)
	})

	t.Run("filters", func(t *testing.T) {
		tests := []struct {
			name string
			q    audit.Query
			want int
		}{
			{"actor by username", audit.Query{Actor: "bob"}, 2},
			{"actor by subject", audit.Query{Actor: "alice-sub"}, 2},
			{"action", audit.Query{Action: audit.ActionApply}, 2},
			{"outcome", audit.Query{Outcome: audit.OutcomeDenied}, 2},
			{"kind", audit.Query{Kind: "Secret"}, 1},
			{"namespace and name", audit.Query{Namespace: "default", Name: "p1"}, 3},
			{"since", audit.Query{Since: base.Add(2 * time.Minute)}, 2},
			{"until", audit.Query{Until: base.Add(time.Minute)}, 1},
			{"combined", audit.Query{Actor: "bob", Outcome: audit.OutcomeDenied, Kind: "Prompt"}, 1},
			{"no match", audit.Query{Actor: "carol"}, 0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, _, err := store.ListAuditEvents(ctx, tt.q)
				require.NoError(t, err)
				assert.Len(t, got, tt.want)
			})
		}
	})

	t.Run("pages", func(t *testing.T) {
		var seen []int64
		cursor := ""
		for range 3 {
			got, next, err := store.ListAuditEvents(ctx, audit.Query{Limit: 3, Cursor: cursor})
			require.NoError(t, err)
			for _, e := range got {
				seen = append(seen, e.ID)
			}
			if next == "" {
				break
			}
			cursor = next
		}
		require.Len(t, seen, 4)
		for i := 1; i < len(seen); i++ {
			assert.Greater(t, seen[i-1], seen[i], "newest first, no repeats")
		}
	})

	t.Run("rejects a forged cursor", func(t *testing.T) {
		_, _, err := store.ListAuditEvents(ctx, audit.Query{Cursor: "not-a-cursor"})
		require.ErrorIs(t, err, audit.ErrInvalidCursor)
	})

	t.Run("append-only", func(t *testing.T) {
		_, err := pool.Exec(ctx, `UPDATE `+store.qualified+` SET outcome = 'success'`)
		require.ErrorContains(t, err, "append-only")
		_, err = pool.Exec(ctx, `TRUNCATE `+store.qualified)
		require.ErrorContains(t, err, "append-only")
	})

	t.Run("prunes old events in batches", func(t *testing.T) {
		n, err := store.PruneAuditEventsBefore(ctx, base.Add(2*time.Minute), 1)
		require.NoError(t, err)
		assert.EqualValues(t, 1, n)
		n, err = store.PruneAuditEventsBefore(ctx, base.Add(2*time.Minute), 0)
		require.NoError(t, err)
		assert.EqualValues(t, 1, n)
		got, _, err := store.ListAuditEvents(ctx, audit.Query{})
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
}
