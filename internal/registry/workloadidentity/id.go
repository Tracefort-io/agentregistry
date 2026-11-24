// Package workloadidentity asserts the identity of agent workloads: it
// resolves a verified SPIFFE ID to the registered Agent and Deployment it was
// assigned to, from the registry's identity records, and rejects every other
// ID. agentgateway calls it on each request from an agent, after verifying
// the agent's X.509-SVID (mutual TLS) and JWT-SVID (docs/auth/agent-identity-assertion.md).
//
// It decides who an agent is, never what the agent may do.
package workloadidentity

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

// ErrMalformed reports an ID that is not an agent workload's SPIFFE ID in the
// trust domain.
var ErrMalformed = errors.New("not an agent workload SPIFFE ID")

var uid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// AgentID is a parsed agent workload SPIFFE ID:
// spiffe://<trust domain>/org/<org>/agent/<agent>/deployment/<Deployment UID>/instance/<pod UID>.
type AgentID struct {
	TrustDomain   string
	Org           string
	Agent         string
	DeploymentUID string
	InstanceUID   string
}

// Prefix is the ID without its instance: the identity the registry assigned
// to the Deployment, shared by its replicas. It has the form the
// KubernetesWorkload runtime records.
func (a AgentID) Prefix() string {
	return fmt.Sprintf("spiffe://%s/org/%s/agent/%s/deployment/%s/", a.TrustDomain, a.Org, a.Agent, a.DeploymentUID)
}

// String is the full SPIFFE ID.
func (a AgentID) String() string {
	return a.Prefix() + "instance/" + a.InstanceUID
}

// ParseAgentID accepts exactly an agent workload's SPIFFE ID in trustDomain:
// org and agent are DNS labels, both UIDs are lower-case UUIDs, and nothing
// else is present (no extra segments, query, fragment or escapes).
func ParseAgentID(id, trustDomain string) (AgentID, error) {
	prefix := "spiffe://" + trustDomain + "/"
	if trustDomain == "" || !strings.HasPrefix(id, prefix) {
		return AgentID{}, fmt.Errorf("%w: not in trust domain %q", ErrMalformed, trustDomain)
	}
	parts := strings.Split(strings.TrimPrefix(id, prefix), "/")
	if len(parts) != 8 || parts[0] != "org" || parts[2] != "agent" || parts[4] != "deployment" || parts[6] != "instance" {
		return AgentID{}, fmt.Errorf("%w: want org/<org>/agent/<agent>/deployment/<uid>/instance/<uid>", ErrMalformed)
	}
	a := AgentID{TrustDomain: trustDomain, Org: parts[1], Agent: parts[3], DeploymentUID: parts[5], InstanceUID: parts[7]}
	if len(k8svalidation.IsDNS1123Label(a.Org)) > 0 {
		return AgentID{}, fmt.Errorf("%w: org %q is not a DNS label", ErrMalformed, a.Org)
	}
	if len(k8svalidation.IsDNS1123Label(a.Agent)) > 0 {
		return AgentID{}, fmt.Errorf("%w: agent %q is not a DNS label", ErrMalformed, a.Agent)
	}
	if !uid.MatchString(a.DeploymentUID) || !uid.MatchString(a.InstanceUID) {
		return AgentID{}, fmt.Errorf("%w: Deployment and instance UIDs must be UUIDs", ErrMalformed)
	}
	return a, nil
}
