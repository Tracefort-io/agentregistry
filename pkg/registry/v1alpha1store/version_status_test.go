//go:build integration

package v1alpha1store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	pkgdb "github.com/agentregistry-dev/agentregistry/pkg/registry/database"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

func TestDeleteVersions_KeepsTheVersionAndRecordsItsHistory(t *testing.T) {
	store := setupAgentStore(t)
	ctx := context.Background()
	for _, tag := range []string{"a", "b"} {
		_, err := store.Upsert(ctx, taggedAgentObj("foo", tag, "title-"+tag, nil))
		require.NoError(t, err)
	}
	change := v1alpha1store.StatusChange{
		ActorSubject: "sub-1", ActorIssuer: "https://idp", ActorUsername: "charlie",
		ApprovalID: "apr_1", RequestID: "req-1",
	}

	require.NoError(t, store.DeleteVersions(ctx, "default", "foo", "a", change))

	// Reads hide the deleted version; it is kept.
	_, err := store.Get(ctx, "default", "foo", "a")
	require.ErrorIs(t, err, v1alpha1store.ErrVersionDeleted)
	require.ErrorIs(t, err, pkgdb.ErrNotFound)
	kept, err := store.GetIncludingDeleted(ctx, "default", "foo", "a")
	require.NoError(t, err)
	require.NotNil(t, kept.Metadata.DeletionTimestamp)
	tags, err := store.ListTags(ctx, "default", "foo")
	require.NoError(t, err)
	require.Len(t, tags, 1)
	require.Equal(t, "b", tags[0].Metadata.Tag)

	history, err := store.VersionStatusHistory(ctx, "default", "foo", "a")
	require.NoError(t, err)
	require.Equal(t, []v1alpha1store.VersionStatusEvent{{
		PreviousStatus: v1alpha1store.VersionStatusActive,
		Status:         v1alpha1store.VersionStatusDeleted,
		StatusChange:   change,
	}}, history)
	history, err = store.VersionStatusHistory(ctx, "default", "foo", "b")
	require.NoError(t, err)
	require.Empty(t, history, "a version without a status change is active")

	// Deleting a deleted version finds nothing live.
	require.ErrorIs(t, store.DeleteVersions(ctx, "default", "foo", "a", change), pkgdb.ErrNotFound)

	// No tag deletes every live tag.
	require.NoError(t, store.DeleteVersions(ctx, "default", "foo", "", v1alpha1store.StatusChange{}))
	_, err = store.Get(ctx, "default", "foo", "b")
	require.ErrorIs(t, err, v1alpha1store.ErrVersionDeleted)
	require.ErrorIs(t, store.DeleteVersions(ctx, "default", "foo", "", v1alpha1store.StatusChange{}), pkgdb.ErrNotFound)

	// The garbage collector never removes a deleted version.
	purged, err := store.PurgeFinalized(ctx)
	require.NoError(t, err)
	require.Zero(t, purged)
	_, err = store.GetIncludingDeleted(ctx, "default", "foo", "b")
	require.NoError(t, err)
}

func TestVersionStatusEvents_AreAppendOnly(t *testing.T) {
	pool := v1alpha1store.NewTestPool(t)
	store := v1alpha1store.NewStore(pool, v1alpha1store.TestSchema(), "agents")
	ctx := context.Background()
	_, err := store.Upsert(ctx, taggedAgentObj("foo", "a", "t", nil))
	require.NoError(t, err)
	require.NoError(t, store.DeleteVersions(ctx, "default", "foo", "a", v1alpha1store.StatusChange{}))

	table := v1alpha1store.TestSchema().Qualify("version_status_events")
	tests := []struct{ name, sql string }{
		{"update", fmt.Sprintf(`UPDATE %s SET status = 'active'`, table)},
		{"delete", fmt.Sprintf(`DELETE FROM %s`, table)},
		{"truncate", fmt.Sprintf(`TRUNCATE %s`, table)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, tt.sql)
			require.ErrorContains(t, err, "version_status_events is append-only")
		})
	}
}

func TestDeleteVersions_OnlyForTaggedStores(t *testing.T) {
	pool := v1alpha1store.NewTestPool(t)
	store := v1alpha1store.NewMutableObjectStore(pool, v1alpha1store.TestSchema(), "runtimes")
	require.Error(t, store.DeleteVersions(context.Background(), "default", "x", "", v1alpha1store.StatusChange{}))
}

func TestTagDeleted(t *testing.T) {
	store := setupAgentStore(t)
	ctx := context.Background()
	for _, tag := range []string{"latest", "kept"} {
		_, err := store.Upsert(ctx, taggedAgentObj("foo", tag, "t", nil))
		require.NoError(t, err)
	}
	require.NoError(t, store.DeleteVersions(ctx, "default", "foo", "latest", v1alpha1store.StatusChange{}))

	tests := []struct {
		name, tag, version string
		want               bool
	}{
		{"deleted tag", "latest", "foo", true},
		{"empty tag is the default tag", "", "foo", true},
		{"live tag", "kept", "foo", false},
		{"no such version", "latest", "bar", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.TagDeleted(ctx, "default", tt.version, tt.tag)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
