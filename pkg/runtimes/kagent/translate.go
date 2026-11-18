package kagent

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var errUnsupported = errors.New("unsupported on kagent runtime")

const (
	mcpServerURLCondition           = "MCPServerURL"
	remoteMCPProtocolStreamableHTTP = "STREAMABLE_HTTP"
)

var invalidNameChars = regexp.MustCompile(`[^a-z0-9]+`)

// WorkloadName returns the Kubernetes resource name used by the Kagent
// adapter for an AgentRegistry target.
func WorkloadName(s string) string {
	name := strings.ToLower(strings.TrimSpace(s))
	name = invalidNameChars.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-")
	if name == "" {
		return "resource"
	}
	return name
}

// DeploymentWorkloadName keeps existing remote identities and distinguishes new tenant Deployments.
func DeploymentWorkloadName(deployment *types.DeploymentRecord) string {
	if name := deploymentRuntimeID(deployment); name != "" {
		return name
	}
	identity := deployment.Metadata.NamespaceOrDefault() + "/" + deployment.Metadata.Name
	digest := sha256.Sum256([]byte(identity))
	prefix := WorkloadName(deployment.Metadata.Name)
	if len(prefix) > 50 {
		prefix = strings.TrimRight(prefix[:50], "-")
	}
	return fmt.Sprintf("%s-%x", prefix, digest[:6])
}

// buildRemoteMCPServer translates a registry MCPServer with a remote URL into
// a Kagent RemoteMCPServer. Kagent 1.x runs no MCP server workloads (it no
// longer bundles kmcp), so package-based MCPServers are unsupported.
func buildRemoteMCPServer(in types.ApplyInput, rcfg runtimeConfig) (*unstructured.Unstructured, error) {
	server, ok := in.Target.(*v1alpha1.MCPServer)
	if !ok {
		return nil, fmt.Errorf("build kagent RemoteMCPServer: target is %T, want *v1alpha1.MCPServer", in.Target)
	}
	if server.Spec.Remote == nil || strings.TrimSpace(server.Spec.Remote.URL) == "" {
		return nil, fmt.Errorf(
			"%w: Kagent 1.x runs no MCP server workloads; MCP server %q needs a remote URL",
			errUnsupported, server.Metadata.Name,
		)
	}
	name := DeploymentWorkloadName(in.Deployment)
	labels := map[string]string{managedByLabel: managedByValue}
	maps.Copy(labels, rcfg.Deployment.Labels)

	out := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"description": remoteMCPDescription(server),
			"protocol":    remoteMCPProtocolStreamableHTTP,
			"url":         strings.TrimSpace(server.Spec.Remote.URL),
		},
	}}
	out.SetAPIVersion(kagentGroup + "/" + kagentVersion)
	out.SetKind(kindRemoteMCPServer)
	out.SetName(name)
	out.SetNamespace(targetNamespace(rcfg))
	out.SetLabels(labels)
	return out, nil
}

// remoteMCPDescription is required by Kagent; it falls back to the
// registry name when the MCPServer has no description.
func remoteMCPDescription(server *v1alpha1.MCPServer) string {
	if description := strings.TrimSpace(server.Spec.Description); description != "" {
		return description
	}
	return server.Metadata.Name
}
