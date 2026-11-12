package registry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/internal/registry/controller"
	"github.com/agentregistry-dev/agentregistry/internal/registry/leader"
	"github.com/agentregistry-dev/agentregistry/pkg/gitutil"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

// serviceAccountNamespaceFile holds the pod's namespace in Kubernetes.
const serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// buildElector returns the elector LEADER_ELECTION selects.
func buildElector(cfg *config.Config, pool *pgxpool.Pool) (leader.Elector, error) {
	timing := leader.Timing{
		LeaseDuration: cfg.LeaderElectionLeaseDuration,
		RenewDeadline: cfg.LeaderElectionRenewDeadline,
		RetryPeriod:   cfg.LeaderElectionRetryPeriod,
	}
	switch cfg.LeaderElection {
	case config.LeaderElectionPostgres:
		return &leader.Postgres{ConnConfig: pool.Config().ConnConfig, Name: cfg.LeaderElectionName, Timing: timing}, nil
	case config.LeaderElectionKubernetes:
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("leader election kubernetes needs to run in a pod: %w", err)
		}
		client, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			return nil, fmt.Errorf("kubernetes client: %w", err)
		}
		namespace := cfg.LeaderElectionNamespace
		if namespace == "" {
			raw, err := os.ReadFile(serviceAccountNamespaceFile)
			if err != nil {
				return nil, fmt.Errorf("set LEADER_ELECTION_NAMESPACE: cannot read the pod's namespace: %w", err)
			}
			namespace = strings.TrimSpace(string(raw))
		}
		identity := cfg.LeaderElectionIdentity
		if identity == "" {
			if identity, err = os.Hostname(); err != nil {
				return nil, fmt.Errorf("set LEADER_ELECTION_IDENTITY: %w", err)
			}
		}
		return &leader.Lease{Client: client, Namespace: namespace, Name: cfg.LeaderElectionName, Identity: identity, Timing: timing}, nil
	default:
		return leader.Always{}, nil
	}
}

// controllerTerms runs the background controllers inside leadership terms:
// the Deployment controller through its Leadership channel, and the
// controllers startOthers starts (Plugin, Skill), fresh for every term.
type controllerTerms struct {
	deployment        chan context.Context
	deploymentStopped chan struct{}
	startOthers       func(term context.Context) (stop func())
}

func newControllerTerms(startOthers func(term context.Context) (stop func())) *controllerTerms {
	return &controllerTerms{
		deployment:        make(chan context.Context),
		deploymentStopped: make(chan struct{}, 1),
		startOthers:       startOthers,
	}
}

// deploymentTermStopped is the Deployment controller's TermStopped hook.
func (c *controllerTerms) deploymentTermStopped() {
	c.deploymentStopped <- struct{}{}
}

// lead runs one term and returns once every controller it started has
// stopped, so the elector releases leadership only after that.
func (c *controllerTerms) lead(term context.Context) {
	delivered := false
	select {
	case c.deployment <- term:
		delivered = true
	case <-term.Done():
	}
	stopOthers := c.startOthers(term)
	<-term.Done()
	stopOthers()
	if delivered {
		<-c.deploymentStopped
	}
}

// run campaigns with e until ctx ends or the returned stop is called; stop
// ends the current term, waits for its controllers and releases leadership.
func (c *controllerTerms) run(ctx context.Context, e leader.Elector) (stop func()) {
	electionCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(electionCtx, c.lead)
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// startPinningControllers starts fresh Plugin and Skill controllers (they
// are single-use) under term, and returns a func that stops both and waits.
func startPinningControllers(term context.Context, pool *pgxpool.Pool, stores map[string]*v1alpha1store.Store, git gitutil.Source) (stop func()) {
	var stops []func()
	if c, err := controller.NewPluginController(pool, stores, controller.PluginControllerDeps{Git: git}); err != nil {
		slog.Error("create plugin controller", "error", err)
	} else if c != nil {
		if err := c.Start(term); err != nil {
			slog.Error("start plugin controller", "error", err)
		} else {
			stops = append(stops, c.Stop)
		}
	}
	if c, err := controller.NewSkillController(pool, stores, controller.SkillControllerDeps{Git: git}); err != nil {
		slog.Error("create skill controller", "error", err)
	} else if c != nil {
		if err := c.Start(term); err != nil {
			slog.Error("start skill controller", "error", err)
		} else {
			stops = append(stops, c.Stop)
		}
	}
	return func() {
		for _, stop := range stops {
			stop()
		}
	}
}
