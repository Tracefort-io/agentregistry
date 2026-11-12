// Package leader elects one registry replica to run the background
// controllers (Deployment reconciliation and discovery, Plugin and Skill
// source pinning). Every replica serves the API; only the leader changes
// things outside the registry.
//
// Two mechanisms are built in: a Postgres session advisory lock (the
// default; it needs nothing beyond the registry's database) and a
// Kubernetes Lease. All replicas of one registry must use the same one: the
// two do not see each other.
package leader

import (
	"context"
	"hash/fnv"
	"time"

	"github.com/agentregistry-dev/agentregistry/pkg/logging"
)

var logger = logging.New("leader-election")

// Elector campaigns for leadership.
type Elector interface {
	// Run campaigns until ctx ends. Each time this replica becomes leader it
	// calls lead with a term context that is canceled when leadership is
	// lost or ctx ends. Run waits for lead to return before it releases
	// leadership or campaigns again, so the work of one term has stopped
	// before another replica (or another term here) can start.
	Run(ctx context.Context, lead func(term context.Context))
}

// Timing for an Elector. The leader must give up before anyone else can
// take over: RetryPeriod < RenewDeadline < LeaseDuration.
type Timing struct {
	// LeaseDuration is how long others wait for a silent leader before
	// taking over (Kubernetes Lease).
	LeaseDuration time.Duration
	// RenewDeadline is how long the leader keeps trying to renew, or to
	// confirm its Postgres connection, before it stops leading.
	RenewDeadline time.Duration
	// RetryPeriod is how often replicas campaign, and how often the leader
	// renews or checks its connection.
	RetryPeriod time.Duration
}

// DefaultTiming matches the Kubernetes components' defaults.
var DefaultTiming = Timing{LeaseDuration: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second}

// Always leads for as long as ctx lasts: one term, no election. For a
// single replica, or when leadership is decided outside the registry.
type Always struct{}

// Run calls lead once with ctx.
func (Always) Run(ctx context.Context, lead func(term context.Context)) {
	lead(ctx)
}

// lockKey maps an election name to a Postgres advisory lock key.
func lockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("agentregistry/leader/" + name))
	return int64(h.Sum64()) //nolint:gosec // any 64-bit value is a valid key
}

// sleep waits d or until ctx ends, and reports whether ctx is still live.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
