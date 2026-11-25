// Package agentgateway writes agentgateway's configuration for MCP servers:
// for each live tag of every MCPServer with spec.remote, an
// AgentgatewayBackend for the server, an HTTPRoute on the gateway's listener
// for agents, and an AgentgatewayPolicy that sends every MCP message to the
// guardrail callout. The callout is the PEP: it authorizes the message for
// the agent the listener's identity check resolved
// (docs/auth/agent-identity-assertion.md) and, for a server with
// spec.credential, fetches the credential from OpenBao as the calling agent
// after the call is allowed and has the gateway inject it.
//
// The gateway, not the agent, holds the route to the server; the agent never
// holds the server's credential.
package agentgateway

import (
	"errors"
	"fmt"
	"strings"

	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

// Config says which gateway carries MCP routes and how it authenticates
// agents and reaches the guardrail callout.
type Config struct {
	// Namespace holds the generated objects; it is the Gateway's namespace.
	Namespace string
	// Gateway and Listener name the Gateway and its listener for agents,
	// whose own policy asserts the agent's identity before routing.
	Gateway  string
	Listener string
	// GuardrailService and GuardrailPort name the guardrail callout's
	// Service in Namespace (the ExtMcp server).
	GuardrailService string
	GuardrailPort    int
	// OpenBaoSVIDHeader carries the agent's JWT-SVID for OpenBao; only the
	// guardrail callout receives it, and it is removed before the upstream
	// call.
	OpenBaoSVIDHeader string
	// OpenBaoAuthMount is the JWT auth method in each org's OpenBao
	// namespace that the credential grants' roles belong to.
	OpenBaoAuthMount string
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	for field, value := range map[string]string{
		"namespace": c.Namespace, "gateway": c.Gateway, "listener": c.Listener,
		"guardrail service": c.GuardrailService,
	} {
		if problems := k8svalidation.IsDNS1123Subdomain(value); value == "" || len(problems) > 0 {
			errs = append(errs, fmt.Errorf("gateway config: %s %q is not a Kubernetes name", field, value))
		}
	}
	if c.GuardrailPort < 1 || c.GuardrailPort > 65535 {
		errs = append(errs, fmt.Errorf("gateway config: guardrail port %d is out of range", c.GuardrailPort))
	}
	if problems := k8svalidation.IsHTTPHeaderName(c.OpenBaoSVIDHeader); c.OpenBaoSVIDHeader == "" || len(problems) > 0 {
		errs = append(errs, fmt.Errorf("gateway config: OpenBao SVID header %q is not a header name", c.OpenBaoSVIDHeader))
	}
	if strings.Trim(c.OpenBaoAuthMount, "/") == "" {
		errs = append(errs, errors.New("gateway config: an OpenBao auth mount is required"))
	}
	return errors.Join(errs...)
}
