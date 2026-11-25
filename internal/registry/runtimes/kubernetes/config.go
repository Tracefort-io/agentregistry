// Package kubernetes runs registry Agents as Kubernetes workloads that hold
// no credentials of their own: each replica gets a per-instance SPIFFE
// identity from SPIRE, and may reach only agentgateway.
//
// For a Deployment of an Agent with a container image, the adapter creates,
// in the namespace of the Deployment's organization (<namespacePrefix><org>,
// where the org is the registry namespace):
//
//   - a ServiceAccount without a Kubernetes API token;
//   - a Deployment whose pods carry the label tracefort.io/agent=<agent>,
//     mount the SPIFFE Workload API (CSI driver csi.spiffe.io) and are told
//     where agentgateway and Temporal are, and which SPIFFE ID the gateway
//     must present;
//   - a NetworkPolicy that admits no ingress and lets the pods reach only
//     agentgateway and cluster DNS.
//
// The pods' SPIFFE IDs come from the org's ClusterSPIFFEID, which the
// platform creates when it onboards the org:
// spiffe://<trust domain>/org/<org>/agent/<agent>/deployment/<Deployment
// UID>/instance/<pod UID>, built from the pods' labels. Both UIDs are never
// reused, so no SPIFFE ID is ever recycled. The adapter never writes
// ClusterSPIFFEIDs; it records the ID prefix as the Deployment's
// ActorSubject.
package kubernetes

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

const (
	// RuntimeType is the Runtime spec.type this adapter serves.
	RuntimeType = "KubernetesWorkload"

	defaultNamespacePrefix = "org-"
	maxReplicas            = 50
	maxUID                 = 2147483647
	maxArgs                = 64
	maxArgLength           = 4096
)

// Registers the runtime type with the admission validator so
// Runtime{spec.type: KubernetesWorkload} passes Validate.
func init() {
	v1alpha1.KnownRuntimeTypes[RuntimeType] = struct{}{}
	if err := v1alpha1.RegisterRuntimeConfigValidator(RuntimeType, func(config map[string]any) error {
		_, err := decodeRuntimeConfig(config)
		return err
	}); err != nil {
		panic(err)
	}
}

// runtimeConfig is a KubernetesWorkload Runtime's spec.config.
type runtimeConfig struct {
	// TrustDomain is the SPIFFE trust domain the org's ClusterSPIFFEID uses.
	TrustDomain string `json:"trustDomain"`
	// NamespacePrefix is prepended to the org to form the workload namespace.
	NamespacePrefix string         `json:"namespacePrefix,omitempty"`
	Gateway         gatewayConfig  `json:"gateway"`
	Temporal        temporalConfig `json:"temporal"`
}

// gatewayConfig says where agentgateway is and how to recognise it.
type gatewayConfig struct {
	// URL is the gateway's TLS listener for agents (https).
	URL string `json:"url"`
	// SPIFFEID is the ID the gateway's X.509-SVID must carry; agents check
	// it before they send their own JWT-SVID.
	SPIFFEID string `json:"spiffeID"`
	// Namespace and PodLabels select the gateway's pods, the only
	// destination the workloads' NetworkPolicy allows besides DNS.
	Namespace string            `json:"namespace"`
	PodLabels map[string]string `json:"podLabels"`
	// Audience the agent's JWT-SVID for the gateway carries (default
	// "agentgateway"); the gateway accepts no other
	// (docs/auth/agent-identity-assertion.md).
	Audience string `json:"audience,omitempty"`
	// OpenBaoAudience is the audience of the agent's second JWT-SVID, which
	// the gateway's guardrail callout uses to fetch MCP server credentials
	// as the agent (default "openbao"; the registry's
	// OPENBAO_WORKLOAD_AUDIENCE). Agents send it in OpenBaoSVIDHeader
	// (default "x-openbao-svid"; the registry's GATEWAY_OPENBAO_SVID_HEADER).
	OpenBaoAudience   string `json:"openBaoAudience,omitempty"`
	OpenBaoSVIDHeader string `json:"openBaoSVIDHeader,omitempty"`
}

// Defaults of gatewayConfig when the Runtime sets none; they match the
// registry's defaults.
const (
	defaultGatewayAudience   = "agentgateway"
	defaultOpenBaoAudience   = "openbao"
	defaultOpenBaoSVIDHeader = "x-openbao-svid"
)

// temporalConfig says where the Temporal frontend is (through agentgateway).
type temporalConfig struct {
	Address string `json:"address"`
}

// deployConfig is a Deployment's spec.runtimeConfig.
type deployConfig struct {
	// Replicas defaults to 1.
	Replicas *int32 `json:"replicas,omitempty"`
	// Command and Args replace the image's entrypoint and arguments.
	Command []string `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// RunAsUser runs the container as this user, for images whose default
	// user is root; Pod Security "restricted" refuses root, so it must not
	// be 0.
	RunAsUser *int64 `json:"runAsUser,omitempty"`
}

func decodeJSONMap(m map[string]any, target any) error {
	if len(m) == 0 {
		return nil
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func decodeRuntimeConfig(m map[string]any) (runtimeConfig, error) {
	var cfg runtimeConfig
	if err := decodeJSONMap(m, &cfg); err != nil {
		return runtimeConfig{}, fmt.Errorf("decode %s runtime config: %w", RuntimeType, err)
	}
	if cfg.NamespacePrefix == "" {
		cfg.NamespacePrefix = defaultNamespacePrefix
	}
	for field, def := range map[*string]string{
		&cfg.Gateway.Audience:          defaultGatewayAudience,
		&cfg.Gateway.OpenBaoAudience:   defaultOpenBaoAudience,
		&cfg.Gateway.OpenBaoSVIDHeader: defaultOpenBaoSVIDHeader,
	} {
		if strings.TrimSpace(*field) == "" {
			*field = def
		}
	}
	if err := cfg.validate(); err != nil {
		return runtimeConfig{}, fmt.Errorf("%s runtime config: %w", RuntimeType, err)
	}
	return cfg, nil
}

func (c runtimeConfig) validate() error {
	if problems := k8svalidation.IsDNS1123Subdomain(c.TrustDomain); c.TrustDomain == "" || len(problems) > 0 {
		return fmt.Errorf("trustDomain %q must be a DNS name", c.TrustDomain)
	}
	if problems := k8svalidation.IsDNS1123Label(c.NamespacePrefix + "a"); len(problems) > 0 {
		return fmt.Errorf("namespacePrefix %q: %s", c.NamespacePrefix, strings.Join(problems, "; "))
	}
	gatewayURL, err := url.Parse(c.Gateway.URL)
	if err != nil || gatewayURL.Scheme != "https" || gatewayURL.Host == "" {
		return fmt.Errorf("gateway.url %q must be an https URL", c.Gateway.URL)
	}
	if !strings.HasPrefix(c.Gateway.SPIFFEID, "spiffe://"+c.TrustDomain+"/") {
		return fmt.Errorf("gateway.spiffeID %q must be in trust domain %s", c.Gateway.SPIFFEID, c.TrustDomain)
	}
	if problems := k8svalidation.IsDNS1123Label(c.Gateway.Namespace); len(problems) > 0 {
		return fmt.Errorf("gateway.namespace %q: %s", c.Gateway.Namespace, strings.Join(problems, "; "))
	}
	if problems := k8svalidation.IsHTTPHeaderName(c.Gateway.OpenBaoSVIDHeader); len(problems) > 0 {
		return fmt.Errorf("gateway.openBaoSVIDHeader %q: %s", c.Gateway.OpenBaoSVIDHeader, strings.Join(problems, "; "))
	}
	if len(c.Gateway.PodLabels) == 0 {
		return fmt.Errorf("gateway.podLabels must select the gateway's pods")
	}
	for key, value := range c.Gateway.PodLabels {
		if problems := k8svalidation.IsQualifiedName(key); len(problems) > 0 {
			return fmt.Errorf("gateway.podLabels key %q: %s", key, strings.Join(problems, "; "))
		}
		if problems := k8svalidation.IsValidLabelValue(value); len(problems) > 0 {
			return fmt.Errorf("gateway.podLabels[%q] value %q: %s", key, value, strings.Join(problems, "; "))
		}
	}
	if strings.TrimSpace(c.Temporal.Address) == "" {
		return fmt.Errorf("temporal.address is required")
	}
	return nil
}

func decodeDeployConfig(m map[string]any) (deployConfig, error) {
	var cfg deployConfig
	if err := decodeJSONMap(m, &cfg); err != nil {
		return deployConfig{}, fmt.Errorf("decode runtimeConfig: %w", err)
	}
	if cfg.Replicas != nil && (*cfg.Replicas < 1 || *cfg.Replicas > maxReplicas) {
		return deployConfig{}, fmt.Errorf("runtimeConfig.replicas must be between 1 and %d", maxReplicas)
	}
	if cfg.RunAsUser != nil && (*cfg.RunAsUser < 1 || *cfg.RunAsUser > maxUID) {
		return deployConfig{}, fmt.Errorf("runtimeConfig.runAsUser must be a non-root user ID (1 to %d)", maxUID)
	}
	for field, values := range map[string][]string{"command": cfg.Command, "args": cfg.Args} {
		if len(values) > maxArgs {
			return deployConfig{}, fmt.Errorf("runtimeConfig.%s may have at most %d entries", field, maxArgs)
		}
		for i, value := range values {
			if value == "" || len(value) > maxArgLength {
				return deployConfig{}, fmt.Errorf("runtimeConfig.%s[%d] must be 1 to %d characters", field, i, maxArgLength)
			}
		}
	}
	return cfg, nil
}

func (c deployConfig) replicas() int32 {
	if c.Replicas == nil {
		return 1
	}
	return *c.Replicas
}

// workloadNamespace is the Kubernetes namespace of an org's agent workloads.
func (c runtimeConfig) workloadNamespace(org string) string {
	return c.NamespacePrefix + org
}

// agentIDPrefix is the SPIFFE ID prefix every replica of one registry
// Deployment shares; the org's ClusterSPIFFEID appends instance/<pod UID>.
// The Deployment's UID is never reused, so neither is the prefix: an agent
// or Deployment re-created under the same name gets new IDs.
func (c runtimeConfig) agentIDPrefix(org, agent, deploymentUID string) string {
	return fmt.Sprintf("spiffe://%s/org/%s/agent/%s/deployment/%s/", c.TrustDomain, org, agent, deploymentUID)
}
