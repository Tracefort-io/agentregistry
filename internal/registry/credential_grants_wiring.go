package registry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/internal/registry/controller"
	"github.com/agentregistry-dev/agentregistry/internal/registry/credentialgrants"
	internaldb "github.com/agentregistry-dev/agentregistry/internal/registry/database"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/secret"
	"github.com/agentregistry-dev/agentregistry/pkg/secret/openbao"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// wireCredentialGrants grants MCP server credentials to agents' workload
// identities when Secrets live in OpenBao org namespaces, and hooks the
// grants into the Deployment controller: rebuilt on every repair pass and
// after every identity change, and withdrawn before a revocation is recorded.
// Without org namespaces there is nothing to grant.
func wireCredentialGrants(cfg *config.Config, payload secret.Store, stores map[string]*v1alpha1store.Store, controllerConfig *controller.ControllerConfig) error {
	store, ok := payload.(*openbao.Store)
	if !ok || store.OrgNamespacePrefix() == "" {
		return nil
	}
	deployments := stores[v1alpha1.KindDeployment]
	if deployments == nil {
		return nil
	}
	writer, err := store.Grants(cfg.OpenBaoWorkloadAuthMount)
	if err != nil {
		return fmt.Errorf("credential grants: %w", err)
	}
	reconciler, err := credentialgrants.New(writer, store,
		listAllDeployments(deployments), deployments.RevokedIdentities, internaldb.NewGetter(stores),
		credentialgrants.Config{OrgPrefix: store.OrgNamespacePrefix(), Audience: cfg.OpenBaoWorkloadAudience})
	if err != nil {
		return err
	}
	sync := func(ctx context.Context) {
		if err := reconciler.Sync(auth.WithSystemContext(ctx)); err != nil {
			slog.Error("credential grants: sync failed; the next repair pass retries", "error", err)
		}
	}
	controllerConfig.BeforeIdentityRevoked = func(ctx context.Context, prefix string) error {
		return reconciler.Revoke(auth.WithSystemContext(ctx), prefix)
	}
	controllerConfig.AfterIdentityChanged = sync
	controllerConfig.AfterRefresh = sync
	return nil
}

// listAllDeployments lists every Deployment, terminating ones included.
func listAllDeployments(store *v1alpha1store.Store) credentialgrants.DeploymentLister {
	return func(ctx context.Context) ([]*types.DeploymentRecord, error) {
		var out []*types.DeploymentRecord
		cursor := ""
		for {
			rows, next, err := store.List(ctx, v1alpha1store.ListOpts{Limit: 500, Cursor: cursor, IncludeTerminating: true})
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				record, err := types.DeploymentRecordFromRaw(row)
				if err != nil {
					return nil, err
				}
				out = append(out, record)
			}
			if next == "" {
				return out, nil
			}
			cursor = next
		}
	}
}
