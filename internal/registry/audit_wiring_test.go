package registry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
)

type fakePruner struct {
	mu      sync.Mutex
	batches []int64
	err     error
	calls   int
	befores []time.Time
}

func (f *fakePruner) PruneAuditEventsBefore(_ context.Context, before time.Time, _ int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.befores = append(f.befores, before)
	if f.err != nil {
		return 0, f.err
	}
	if len(f.batches) == 0 {
		return 0, nil
	}
	n := f.batches[0]
	f.batches = f.batches[1:]
	return n, nil
}

func TestPruneAudit(t *testing.T) {
	t.Run("deletes in batches until a short one", func(t *testing.T) {
		p := &fakePruner{batches: []int64{auditPruneBatch, auditPruneBatch, 7}}
		assert.EqualValues(t, 2*auditPruneBatch+7, pruneAudit(context.Background(), p, time.Now()))
		assert.Equal(t, 3, p.calls)
	})
	t.Run("stops on an error", func(t *testing.T) {
		p := &fakePruner{err: errors.New("db down")}
		assert.Zero(t, pruneAudit(context.Background(), p, time.Now()))
		assert.Equal(t, 1, p.calls)
	})
}

func TestRunAuditRetention(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	p := &fakePruner{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runAuditRetention(ctx, p, 90*24*time.Hour, time.Hour, func() time.Time { return now })
		close(done)
	}()
	require.Eventually(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.calls > 0
	}, time.Second, 10*time.Millisecond, "prunes once at start")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retention loop did not stop")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	assert.Equal(t, now.Add(-90*24*time.Hour), p.befores[0])
}

func TestBuildAuditDisabledKeepsExtraRecorder(t *testing.T) {
	extra := audit.RecorderFunc(func(context.Context, audit.Event) {})
	w, err := buildAudit(context.Background(), &config.Config{AuditEnabled: false}, nil, extra)
	require.NoError(t, err)
	assert.NotNil(t, w.recorder)
	assert.Nil(t, w.lister, "no /v0/audit without the built-in log")
	assert.NoError(t, w.shutdown(context.Background()))
}
