package leader

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var fastTiming = Timing{LeaseDuration: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 100 * time.Millisecond}

// replica runs an elector and records its terms.
type replica struct {
	name    string
	leading atomic.Bool
	terms   atomic.Int32
	stop    context.CancelFunc
	done    chan struct{}
}

// runReplica starts e. While leading, the term records that it holds
// leadership and fails the test if another replica holds it too.
func runReplica(t *testing.T, name string, e Elector, holders *atomic.Int32, onTermEnd func()) *replica {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &replica{name: name, stop: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		e.Run(ctx, func(term context.Context) {
			if n := holders.Add(1); n != 1 {
				t.Errorf("%s leads while %d replicas lead", name, n)
			}
			r.terms.Add(1)
			r.leading.Store(true)
			<-term.Done()
			if onTermEnd != nil {
				onTermEnd()
			}
			r.leading.Store(false)
			holders.Add(-1)
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

func leaseFor(client *fake.Clientset, identity string) *Lease {
	return &Lease{Client: client, Namespace: "ns", Name: "agentregistry-controllers", Identity: identity, Timing: fastTiming}
}

func TestLeaseElectsOneAndHandsOver(t *testing.T) {
	client := fake.NewClientset()
	var holders atomic.Int32
	a := runReplica(t, "a", leaseFor(client, "pod-a"), &holders, nil)
	require.Eventually(t, a.leading.Load, 5*time.Second, 20*time.Millisecond, "the first replica leads")

	b := runReplica(t, "b", leaseFor(client, "pod-b"), &holders, nil)
	time.Sleep(500 * time.Millisecond)
	assert.False(t, b.leading.Load(), "a second replica waits")

	lease, err := client.CoordinationV1().Leases("ns").Get(context.Background(), "agentregistry-controllers", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "pod-a", *lease.Spec.HolderIdentity)

	// A clean shutdown releases the Lease, so b takes over without waiting
	// out the lease duration.
	start := time.Now()
	a.stop()
	<-a.done
	require.Eventually(t, b.leading.Load, 5*time.Second, 20*time.Millisecond, "b takes over")
	assert.Less(t, time.Since(start), fastTiming.LeaseDuration, "released, not expired")
}

func TestLeaseReleasesOnlyAfterTheTermStops(t *testing.T) {
	client := fake.NewClientset()
	var holders atomic.Int32
	var mu sync.Mutex
	var released []string

	// a's term takes a while to stop; b must not lead until it has.
	a := runReplica(t, "a", leaseFor(client, "pod-a"), &holders, func() {
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		released = append(released, "a stopped")
		mu.Unlock()
	})
	require.Eventually(t, a.leading.Load, 5*time.Second, 20*time.Millisecond)
	b := runReplica(t, "b", leaseFor(client, "pod-b"), &holders, nil)

	a.stop()
	require.Eventually(t, b.leading.Load, 5*time.Second, 20*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"a stopped"}, released, "a's work stopped before b led")
}

func TestLeaseRejectsInvalidTiming(t *testing.T) {
	l := leaseFor(fake.NewClientset(), "pod-a")
	l.Timing = Timing{LeaseDuration: time.Second, RenewDeadline: 2 * time.Second, RetryPeriod: 100 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Run(context.Background(), func(context.Context) { t.Error("must not lead") })
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not give up on an invalid configuration")
	}
}

func TestAlways(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var led bool
	Always{}.Run(ctx, func(term context.Context) { led = term.Err() != nil })
	assert.True(t, led, "leads once, for ctx")
}
