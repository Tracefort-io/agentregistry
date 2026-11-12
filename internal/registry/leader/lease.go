package leader

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Lease elects a leader with a Kubernetes Lease (coordination.k8s.io/v1),
// as the Kubernetes control plane does: the holder renews the Lease every
// RetryPeriod, stops leading if it cannot renew within RenewDeadline, and
// others take over once it has been silent for LeaseDuration.
//
// The registry's service account needs get, create and update on leases in
// Namespace.
type Lease struct {
	Client    kubernetes.Interface
	Namespace string
	// Name is the Lease's name; replicas with the same name compete.
	Name string
	// Identity names this replica in the Lease, normally the pod name.
	Identity string
	Timing   Timing

	// terms serializes lead calls: client-go starts the leading callback in
	// its own goroutine, which can outlive the elector that started it.
	terms sync.Mutex
}

// Run campaigns until ctx ends.
func (l *Lease) Run(ctx context.Context, lead func(term context.Context)) {
	defer func() {
		// Wait for a leading callback that started as ctx ended.
		l.terms.Lock()
		defer l.terms.Unlock()
	}()
	for ctx.Err() == nil {
		if err := l.runOnce(ctx, lead); err != nil {
			logger.Error("leader election: invalid Lease configuration", "error", err)
			return
		}
		sleep(ctx, l.Timing.RetryPeriod)
	}
}

// runOnce campaigns until this replica has led once, or ctx ends.
func (l *Lease) runOnce(ctx context.Context, lead func(term context.Context)) error {
	// The elector's own context ends only after lead has returned, so the
	// Lease is released after this term's work has stopped, never before.
	electorCtx, stopElector := context.WithCancel(context.Background())
	defer stopElector()

	var leading atomic.Bool
	leadDone := make(chan struct{})
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Namespace: l.Namespace, Name: l.Name},
			Client:     l.Client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: l.Identity},
		},
		LeaseDuration:   l.Timing.LeaseDuration,
		RenewDeadline:   l.Timing.RenewDeadline,
		RetryPeriod:     l.Timing.RetryPeriod,
		ReleaseOnCancel: true,
		Name:            l.Name,
		Callbacks: leaderelection.LeaderCallbacks{
			// renewCtx ends when renewing fails or electorCtx ends.
			OnStartedLeading: func(renewCtx context.Context) {
				l.terms.Lock()
				defer l.terms.Unlock()
				leading.Store(true)
				defer stopElector()
				defer close(leadDone)
				if renewCtx.Err() != nil || ctx.Err() != nil {
					return // acquired just as the elector stopped
				}
				logger.Info("became leader", "election", l.Name, "mechanism", "kubernetes-lease", "identity", l.Identity)
				term, cancel := context.WithCancel(renewCtx)
				stop := context.AfterFunc(ctx, cancel)
				lead(term)
				stop()
				cancel()
			},
			OnStoppedLeading: func() {
				if leading.Load() {
					logger.Info("stopped leading", "election", l.Name, "identity", l.Identity)
				}
			},
		},
	})
	if err != nil {
		return fmt.Errorf("lease elector: %w", err)
	}

	// While campaigning, stop when ctx ends. While leading, lead's return
	// stops the elector instead.
	stopCampaign := context.AfterFunc(ctx, func() {
		if !leading.Load() {
			stopElector()
		}
	})
	defer stopCampaign()

	elector.Run(electorCtx)
	if leading.Load() {
		<-leadDone
	}
	return nil
}
