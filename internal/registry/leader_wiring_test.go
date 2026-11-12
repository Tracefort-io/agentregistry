package registry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/internal/registry/leader"
)

// recorder keeps the order of lifecycle events.
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// electorFunc adapts a function to leader.Elector.
type electorFunc func(ctx context.Context, lead func(context.Context))

func (f electorFunc) Run(ctx context.Context, lead func(context.Context)) { f(ctx, lead) }

func TestControllerTermsReleaseOnlyAfterEveryControllerStopped(t *testing.T) {
	rec := &recorder{}
	terms := newControllerTerms(func(term context.Context) func() {
		rec.add("others started")
		return func() { rec.add("others stopped") }
	})

	// A stand-in for the Deployment controller's leadership runner.
	go func() {
		for term := range terms.deployment {
			rec.add("deployment started")
			<-term.Done()
			time.Sleep(50 * time.Millisecond) // workers take a moment to stop
			rec.add("deployment stopped")
			terms.deploymentTermStopped()
		}
	}()

	elector := electorFunc(func(ctx context.Context, lead func(context.Context)) {
		term, cancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel() // leadership lost
		}()
		lead(term)
		rec.add("leadership released")
		<-ctx.Done()
	})

	stop := terms.run(context.Background(), elector)
	require.Eventually(t, func() bool {
		events := rec.list()
		return len(events) > 0 && events[len(events)-1] == "leadership released"
	}, 2*time.Second, 10*time.Millisecond)
	stop()

	events := rec.list()
	assert.ElementsMatch(t, []string{"deployment started", "others started"}, events[:2])
	assert.Equal(t, "leadership released", events[len(events)-1], "released last: %v", events)
	assert.Contains(t, events, "others stopped")
	assert.Contains(t, events, "deployment stopped")
}

func TestControllerTermsStopEndsTheTerm(t *testing.T) {
	terms := newControllerTerms(func(context.Context) func() { return func() {} })
	go func() {
		for term := range terms.deployment {
			<-term.Done()
			terms.deploymentTermStopped()
		}
	}()
	stop := terms.run(context.Background(), leader.Always{})
	done := make(chan struct{})
	go func() {
		stop()
		stop() // idempotent
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not end the term")
	}
}

func TestBuildElector(t *testing.T) {
	timed := config.Config{LeaderElectionName: "x", LeaderElectionLeaseDuration: 15 * time.Second,
		LeaderElectionRenewDeadline: 10 * time.Second, LeaderElectionRetryPeriod: 2 * time.Second}

	none := timed
	none.LeaderElection = config.LeaderElectionNone
	e, err := buildElector(&none, nil)
	require.NoError(t, err)
	assert.IsType(t, leader.Always{}, e)

	k8s := timed
	k8s.LeaderElection = config.LeaderElectionKubernetes
	_, err = buildElector(&k8s, nil)
	require.ErrorContains(t, err, "pod", "outside a cluster the Lease mode explains itself")
}
