package audit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
)

type session struct{ p auth.Principal }

func (s session) Principal() auth.Principal { return s.p }

type collector struct {
	mu     sync.Mutex
	events []Event
}

func (c *collector) Record(_ context.Context, e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func TestRecord(t *testing.T) {
	alice := auth.Principal{
		Subject: "alice-sub", Issuer: "https://idp", Username: "alice",
		Actor: []auth.Actor{{Subject: "agent-1", Issuer: "https://idp"}},
	}
	userCtx := authzen.WithRequestID(auth.AuthSessionTo(context.Background(), session{alice}), "req-1")

	tests := []struct {
		name      string
		ctx       context.Context
		wantEvent bool
		wantActor Actor
		wantReqID string
	}{
		{"user", userCtx, true, Actor{Subject: "alice-sub", Issuer: "https://idp", Username: "alice", Via: []string{"agent-1"}}, "req-1"},
		{"client", auth.AuthSessionTo(context.Background(), session{auth.Principal{Subject: "ci", Issuer: "https://idp", IsClient: true}}), true, Actor{Subject: "ci", Issuer: "https://idp", Client: true}, ""},
		{"anonymous", auth.WithPublicContext(context.Background()), true, Actor{}, ""},
		{"no session", context.Background(), true, Actor{}, ""},
		{"the registry itself is not recorded", auth.WithSystemContext(context.Background()), false, Actor{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &collector{}
			Record(tt.ctx, c, Event{Action: ActionApply, Resource: Resource{Kind: "Prompt", Name: "p"}, Outcome: OutcomeSuccess})
			if !tt.wantEvent {
				assert.Empty(t, c.events)
				return
			}
			require.Len(t, c.events, 1)
			e := c.events[0]
			assert.Equal(t, tt.wantActor, e.Actor)
			assert.Equal(t, tt.wantReqID, e.RequestID)
			assert.False(t, e.Time.IsZero())
			assert.Equal(t, "UTC", e.Time.Location().String())
		})
	}

	t.Run("nil recorder", func(t *testing.T) {
		assert.NotPanics(t, func() { Record(userCtx, nil, Event{}) })
	})
}

func TestMulti(t *testing.T) {
	assert.Nil(t, Multi(nil, nil))
	one := &collector{}
	assert.Same(t, one, Multi(nil, one))

	a, b := &collector{}, &collector{}
	Multi(a, nil, b).Record(context.Background(), Event{Action: ActionDelete})
	assert.Len(t, a.events, 1)
	assert.Len(t, b.events, 1)
}

type failingStore struct{ ctxErr error }

func (s *failingStore) InsertAuditEvent(ctx context.Context, _ Event) (int64, error) {
	s.ctxErr = ctx.Err()
	return 0, errors.New("db down")
}

func TestStoreRecorder(t *testing.T) {
	var buf bytes.Buffer
	store := &failingStore{}
	r := StoreRecorder(store, slog.New(slog.NewTextHandler(&buf, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Record(ctx, Event{Action: ActionApply, Resource: Resource{Kind: "Prompt", Name: "p"}, Outcome: OutcomeSuccess})

	require.NoError(t, store.ctxErr, "stored even after the request was cancelled")
	assert.Contains(t, buf.String(), "audit event not stored")
	assert.Contains(t, buf.String(), "db down")
	assert.Contains(t, buf.String(), "name=p")
}
