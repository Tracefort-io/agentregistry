package registry

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/internal/registry/tracing"
	"github.com/agentregistry-dev/agentregistry/internal/registry/workloadidentity"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

var identityCheckLogger = logging.New("agent-identity")

// startIdentityCheckServer serves the agent identity check on
// IDENTITY_CHECK_ADDR, a listener of its own that carries nothing else, so
// it can be exposed to agentgateway alone. It returns nil when disabled.
func startIdentityCheckServer(cfg *config.Config, stores map[string]*v1alpha1store.Store) (*http.Server, error) {
	if cfg.IdentityCheckAddr == "" {
		return nil, nil
	}
	deployments := stores[v1alpha1.KindDeployment]
	if deployments == nil {
		return nil, errors.New("agent identity check: no Deployment store")
	}
	resolver, err := workloadidentity.NewResolver(cfg.IdentityTrustDomain, deployments.IdentityHistory)
	if err != nil {
		return nil, fmt.Errorf("agent identity check: %w", err)
	}
	srv := &http.Server{
		Addr:              cfg.IdentityCheckAddr,
		Handler:           tracing.Handler("agentregistry-identity-check", workloadidentity.NewHandler(resolver, identityCheckLogger)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       cfg.HTTPIdleTimeout,
	}
	go func() {
		slog.Info("agent identity check starting", "address", cfg.IdentityCheckAddr, "trust_domain", cfg.IdentityTrustDomain)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("failed to start the agent identity check", "error", err)
			os.Exit(1)
		}
	}()
	return srv, nil
}
