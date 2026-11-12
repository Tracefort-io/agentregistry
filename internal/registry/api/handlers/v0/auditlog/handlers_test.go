package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
)

type fakeLister struct {
	got    audit.Query
	events []audit.Event
	next   string
	err    error
}

func (f *fakeLister) ListAuditEvents(_ context.Context, q audit.Query) ([]audit.Event, string, error) {
	f.got = q
	return f.events, f.next, f.err
}

func newAPI(t *testing.T, lister *fakeLister, admin bool) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t)
	Register(api, "/v0", Config{Lister: lister, IsAdmin: func(context.Context) bool { return admin }})
	return api
}

func TestListAuditEvents(t *testing.T) {
	when := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	lister := &fakeLister{
		events: []audit.Event{{ID: 7, Time: when, Action: audit.ActionApply, Outcome: audit.OutcomeSuccess,
			Actor: audit.Actor{Subject: "alice-sub", Username: "alice"}, Resource: audit.Resource{Kind: "Prompt", Namespace: "default", Name: "p"}}},
		next: "c2",
	}
	api := newAPI(t, lister, true)

	resp := api.Get("/v0/audit?actor=alice&action=apply&outcome=success&kind=Prompt&namespace=default&name=p" +
		"&since=2026-11-10T00:00:00Z&until=2026-11-12T00:00:00Z&limit=20&cursor=c1")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Equal(t, audit.Query{
		Actor: "alice", Action: "apply", Outcome: "success", Kind: "Prompt", Namespace: "default", Name: "p",
		Since: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), Until: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC),
		Limit: 20, Cursor: "c1",
	}, lister.got)

	var body EventsBody
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Len(t, body.Events, 1)
	assert.Equal(t, int64(7), body.Events[0].ID)
	assert.Equal(t, "alice", body.Events[0].Actor.Username)
	assert.Equal(t, "c2", body.NextCursor)
}

func TestListAuditEvents_Errors(t *testing.T) {
	tests := []struct {
		name   string
		admin  bool
		query  string
		err    error
		want   int
		hidden string
	}{
		{name: "not an admin", admin: false, query: "", want: http.StatusForbidden},
		{name: "bad since", admin: true, query: "?since=yesterday", want: http.StatusBadRequest},
		{name: "bad until", admin: true, query: "?until=2026-13-01", want: http.StatusBadRequest},
		{name: "unknown action", admin: true, query: "?action=publish", want: http.StatusUnprocessableEntity},
		{name: "limit too large", admin: true, query: "?limit=501", want: http.StatusUnprocessableEntity},
		{name: "forged cursor", admin: true, query: "?cursor=x", err: audit.ErrInvalidCursor, want: http.StatusBadRequest},
		{name: "storage failure hides the cause", admin: true, query: "", err: errors.New("pq: relation audit_events on db-7"), want: http.StatusInternalServerError, hidden: "db-7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newAPI(t, &fakeLister{err: tt.err}, tt.admin)
			resp := api.Get("/v0/audit" + tt.query)
			assert.Equal(t, tt.want, resp.Code, resp.Body.String())
			if tt.hidden != "" {
				assert.NotContains(t, resp.Body.String(), tt.hidden)
			}
		})
	}

	t.Run("an empty log is an empty list", func(t *testing.T) {
		resp := newAPI(t, &fakeLister{}, true).Get("/v0/audit")
		require.Equal(t, http.StatusOK, resp.Code)
		assert.JSONEq(t, `{"events":[]}`, resp.Body.String())
	})
}
