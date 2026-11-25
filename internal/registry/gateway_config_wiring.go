package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/agentregistry-dev/agentregistry/internal/registry/api/handlers/v0/crud"
	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/internal/registry/controller"
	"github.com/agentregistry-dev/agentregistry/internal/registry/gateway/agentgateway"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/secret"
	"github.com/agentregistry-dev/agentregistry/pkg/secret/openbao"
)

// wireGatewayConfig writes agentgateway's MCP routes when
// GATEWAY_CONFIG_ENABLED is set: on every repair pass of the elected
// replica, and soon after an MCPServer is applied or deleted (hookGatewayConfig).
// It returns nil when disabled.
func wireGatewayConfig(ctx context.Context, cfg *config.Config, payload secret.Store, stores map[string]*v1alpha1store.Store, controllerConfig *controller.ControllerConfig) (*agentgateway.Reconciler, error) {
	if !cfg.GatewayConfigEnabled {
		return nil, nil
	}
	servers := stores[v1alpha1.KindMCPServer]
	if servers == nil {
		return nil, fmt.Errorf("gateway config: no MCPServer store")
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("gateway config: load in-cluster Kubernetes config: %w", err)
	}
	client, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("gateway config: create Kubernetes client: %w", err)
	}
	// Credentials are fetched from org namespaces only; without them, servers
	// with a credential get no route.
	var locator agentgateway.Locator
	if store, ok := payload.(*openbao.Store); ok && store.OrgNamespacePrefix() != "" {
		locator = store
	}
	reconciler, err := agentgateway.New(agentgateway.NewDynamicClient(client), listAllMCPServers(servers), locator, agentgateway.Config{
		Namespace:         cfg.GatewayNamespace,
		Gateway:           cfg.GatewayName,
		Listener:          cfg.GatewayListener,
		GuardrailService:  cfg.GatewayGuardrailService,
		GuardrailPort:     cfg.GatewayGuardrailPort,
		OpenBaoSVIDHeader: cfg.GatewayOpenBaoSVIDHeader,
		OpenBaoAuthMount:  cfg.OpenBaoWorkloadAuthMount,
	})
	if err != nil {
		return nil, err
	}
	go reconciler.Run(auth.WithSystemContext(ctx))
	previous := controllerConfig.AfterRefresh
	controllerConfig.AfterRefresh = func(ctx context.Context) {
		if previous != nil {
			previous(ctx)
		}
		if err := reconciler.Sync(auth.WithSystemContext(ctx)); err != nil {
			slog.Error("mcp gateway config: sync failed; the next repair pass retries", "error", err)
		}
	}
	slog.Info("mcp gateway config enabled", "namespace", cfg.GatewayNamespace, "gateway", cfg.GatewayName, "listener", cfg.GatewayListener)
	return reconciler, nil
}

// hookGatewayConfig syncs the gateway soon after an MCPServer is applied or
// deleted; the repair pass covers anything a sync misses.
func hookGatewayConfig(hooks *crud.PerKindHooks, reconciler *agentgateway.Reconciler) {
	if reconciler == nil {
		return
	}
	kick := func(context.Context, v1alpha1.Object) error {
		reconciler.Kick()
		return nil
	}
	if hooks.PostUpserts == nil {
		hooks.PostUpserts = map[string]func(context.Context, v1alpha1.Object) error{}
	}
	if hooks.PostDeletes == nil {
		hooks.PostDeletes = map[string]func(context.Context, v1alpha1.Object) error{}
	}
	hooks.PostUpserts[v1alpha1.KindMCPServer] = chainObjectHooks(hooks.PostUpserts[v1alpha1.KindMCPServer], kick)
	hooks.PostDeletes[v1alpha1.KindMCPServer] = chainObjectHooks(hooks.PostDeletes[v1alpha1.KindMCPServer], kick)
}

// listAllMCPServers lists every live MCPServer version.
func listAllMCPServers(store *v1alpha1store.Store) agentgateway.ServerLister {
	return func(ctx context.Context) ([]*v1alpha1.MCPServer, error) {
		var out []*v1alpha1.MCPServer
		cursor := ""
		for {
			rows, next, err := store.List(ctx, v1alpha1store.ListOpts{Limit: 500, Cursor: cursor})
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				server := &v1alpha1.MCPServer{Metadata: row.Metadata}
				if len(row.Spec) > 0 {
					if err := json.Unmarshal(row.Spec, &server.Spec); err != nil {
						return nil, fmt.Errorf("decode MCPServer %s/%s:%s: %w", row.Metadata.Namespace, row.Metadata.Name, row.Metadata.Tag, err)
					}
				}
				out = append(out, server)
			}
			if next == "" {
				return out, nil
			}
			cursor = next
		}
	}
}
