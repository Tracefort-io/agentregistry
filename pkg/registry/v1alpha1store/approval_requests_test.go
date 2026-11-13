//go:build integration

package v1alpha1store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApprovalRequestStore(t *testing.T) {
	pool := NewTestPool(t)
	s := NewApprovalRequestStore(pool, TestSchema())
	ctx := context.Background()

	carol := json.RawMessage(`{"subject":"carol-sub","issuer":"https://idp"}`)
	for i, id := range []string{"arq_1", "arq_2", "arq_3"} {
		require.NoError(t, s.CreateApprovalRequest(ctx, ApprovalRequest{
			ID: id, Verb: "apply", Kind: "Deployment", Namespace: "prod", Name: "bot-" + id,
			Document: json.RawMessage(`{"kind":"Deployment"}`), DocumentSHA256: "abc",
			Requester: carol, RequesterSubject: []string{"carol-sub", "carol-sub", "dave-sub"}[i], RequesterUsername: "carol",
			StatusEndpoint: "https://pdp/access/v1/requests/" + id,
		}))
		time.Sleep(5 * time.Millisecond)
	}

	r, err := s.GetApprovalRequest(ctx, "arq_1")
	require.NoError(t, err)
	assert.Equal(t, ApprovalPending, r.Status)
	assert.JSONEq(t, `{"kind":"Deployment"}`, string(r.Document))
	assert.JSONEq(t, string(carol), string(r.Requester))
	_, err = s.GetApprovalRequest(ctx, "arq_missing")
	require.ErrorIs(t, err, ErrApprovalNotFound)

	mine, _, err := s.ListApprovalRequests(ctx, ApprovalQuery{RequesterSubject: "carol-sub"})
	require.NoError(t, err)
	require.Len(t, mine, 2)
	assert.Equal(t, "arq_2", mine[0].ID, "newest first")

	page1, next, err := s.ListApprovalRequests(ctx, ApprovalQuery{Limit: 2})
	require.NoError(t, err)
	require.Len(t, page1, 2)
	require.NotEmpty(t, next)
	page2, next, err := s.ListApprovalRequests(ctx, ApprovalQuery{Limit: 2, Cursor: next})
	require.NoError(t, err)
	require.Len(t, page2, 1)
	assert.Empty(t, next)
	assert.Equal(t, "arq_1", page2[0].ID)

	// Only one transition from a state wins.
	ok, err := s.TransitionApprovalRequest(ctx, "arq_1", []string{ApprovalPending}, ApprovalApproved, "apr_1", "")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = s.TransitionApprovalRequest(ctx, "arq_1", []string{ApprovalPending}, ApprovalApproved, "apr_9", "")
	require.NoError(t, err)
	assert.False(t, ok, "already approved")
	ok, err = s.TransitionApprovalRequest(ctx, "arq_1", []string{ApprovalApproved}, ApprovalApplying, "", "")
	require.NoError(t, err)
	assert.True(t, ok)
	r, err = s.GetApprovalRequest(ctx, "arq_1")
	require.NoError(t, err)
	assert.Equal(t, ApprovalApplying, r.Status)
	assert.Equal(t, "apr_1", r.ApprovalID, "kept across transitions")

	stuck, err := s.StuckApplyingBefore(ctx, time.Now().Add(time.Minute), 10)
	require.NoError(t, err)
	require.Len(t, stuck, 1)
	assert.Equal(t, "arq_1", stuck[0].ID)

	pending, _, err := s.ListApprovalRequests(ctx, ApprovalQuery{Statuses: []string{ApprovalPending}})
	require.NoError(t, err)
	assert.Len(t, pending, 2)

	_, _, err = s.ListApprovalRequests(ctx, ApprovalQuery{Cursor: "forged"})
	require.Error(t, err)
}
