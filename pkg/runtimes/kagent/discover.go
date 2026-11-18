package kagent

import (
	"context"
	"fmt"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// Discover lists Kagent's Agents and RemoteMCPServers in the Runtime's
// namespace.
func (a *adapter) Discover(ctx context.Context, in types.DiscoverInput) ([]types.DiscoveryResult, error) {
	if in.Runtime == nil {
		return nil, fmt.Errorf("kagent discover: runtime is required")
	}
	rcfg, err := decodeRuntimeConfig(in.Runtime.Spec.Config)
	if err != nil {
		return nil, fmt.Errorf("kagent discover: %w", err)
	}
	client, err := a.newClient()
	if err != nil {
		return nil, fmt.Errorf("build kagent client: %w", err)
	}
	namespace := targetNamespace(rcfg)
	agents, err := client.listAgents(ctx, namespace)
	if err != nil {
		return nil, err
	}
	servers, err := client.listRemoteMCPServers(ctx, namespace)
	if err != nil {
		return nil, err
	}
	out := make([]types.DiscoveryResult, 0, len(agents)+len(servers))
	for _, name := range agents {
		out = append(out, discovered(v1alpha1.KindAgent, name, namespace))
	}
	for _, name := range servers {
		out = append(out, discovered(v1alpha1.KindMCPServer, name, namespace))
	}
	return out, nil
}

func discovered(kind, name, namespace string) types.DiscoveryResult {
	return types.DiscoveryResult{
		TargetKind: kind,
		Name:       name,
		InternalMeta: types.DeploymentInternalMeta{
			RuntimeID:        name,
			RuntimeName:      name,
			RuntimeNamespace: namespace,
		},
	}
}
