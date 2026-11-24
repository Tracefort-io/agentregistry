package kubernetes

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

const (
	// agentLabel names the logical agent; the org's ClusterSPIFFEID puts it
	// in the SPIFFE ID, and only pods carrying it get an identity.
	agentLabel = "tracefort.io/agent"
	// deploymentUIDLabel carries the registry Deployment's UID; the org's
	// ClusterSPIFFEID puts it in the SPIFFE ID, so IDs are never reused.
	deploymentUIDLabel = "tracefort.io/deployment-uid"
	// workloadLabel names this Deployment's objects, one set per registry
	// Deployment (several may run the same agent).
	workloadLabel  = "tracefort.io/workload"
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "agentregistry"

	spiffeVolume    = "spiffe-workload-api"
	spiffeMountPath = "/spiffe-workload-api"
	spiffeCSIDriver = "csi.spiffe.io"
	containerName   = "agent"
)

var errInvalidTarget = errors.New("invalid target")

// Environment the adapter sets; a Deployment's env may not override them.
const (
	envSPIFFESocket    = "SPIFFE_ENDPOINT_SOCKET"
	envGatewayURL      = "AGENTGATEWAY_URL"
	envGatewaySPIFFEID = "AGENTGATEWAY_SPIFFE_ID"
	// envGatewayAudience is the audience of the JWT-SVID the agent sends to
	// the gateway.
	envGatewayAudience = "AGENTGATEWAY_AUDIENCE"
	envTemporalAddress = "TEMPORAL_ADDRESS"
	envOrg             = "TRACEFORT_ORG"
	envAgent           = "TRACEFORT_AGENT"
	envOTLPEndpoint    = "OTEL_EXPORTER_OTLP_ENDPOINT"
)

var reservedEnv = []string{envSPIFFESocket, envGatewayURL, envGatewaySPIFFEID, envGatewayAudience, envTemporalAddress, envOrg, envAgent, envOTLPEndpoint}

// workload is everything the adapter creates for one Deployment.
type workload struct {
	namespace      string
	name           string
	org            string
	agent          string
	actorSubject   string
	serviceAccount *corev1.ServiceAccount
	deployment     *appsv1.Deployment
	networkPolicy  *networkingv1.NetworkPolicy
}

var invalidNameChars = regexp.MustCompile(`[^a-z0-9]+`)

// workloadName is unique per registry Deployment: its name made into a DNS
// label, plus a digest of namespace/name, so names that differ only in
// characters a label can't hold still get different objects. Unlike agent
// names it names no identity, so rewriting it is safe.
func workloadName(deployment *types.DeploymentRecord) string {
	if deployment.InternalMeta.RuntimeName != "" {
		return deployment.InternalMeta.RuntimeName
	}
	identity := deployment.Metadata.NamespaceOrDefault() + "/" + deployment.Metadata.Name
	digest := sha256.Sum256([]byte(identity))
	prefix := strings.Trim(invalidNameChars.ReplaceAllString(strings.ToLower(deployment.Metadata.Name), "-"), "-")
	if len(prefix) > 40 {
		prefix = strings.TrimRight(prefix[:40], "-")
	}
	if prefix == "" {
		prefix = "agent"
	}
	return fmt.Sprintf("%s-%x", prefix, digest[:6])
}

// buildWorkload translates a Deployment of an Agent into its Kubernetes
// objects. Agent and org names become part of SPIFFE IDs, so they must
// already be valid DNS labels: rewriting them could give two agents one ID.
func buildWorkload(in types.ApplyInput, rcfg runtimeConfig, dcfg deployConfig) (*workload, error) {
	agent, ok := in.Target.(*v1alpha1.Agent)
	if !ok {
		return nil, fmt.Errorf("%w: target is %T, want an Agent", errInvalidTarget, in.Target)
	}
	if agent.Spec.Source == nil || strings.TrimSpace(agent.Spec.Source.Image) == "" {
		return nil, fmt.Errorf("%w: agent %q has no container image (spec.source.image)", errInvalidTarget, agent.Metadata.Name)
	}
	org := in.Deployment.Metadata.NamespaceOrDefault()
	if problems := k8svalidation.IsDNS1123Label(org); len(problems) > 0 {
		return nil, fmt.Errorf("%w: org (registry namespace) %q: %s", errInvalidTarget, org, strings.Join(problems, "; "))
	}
	namespace := rcfg.workloadNamespace(org)
	if problems := k8svalidation.IsDNS1123Label(namespace); len(problems) > 0 {
		return nil, fmt.Errorf("%w: workload namespace %q: %s", errInvalidTarget, namespace, strings.Join(problems, "; "))
	}
	agentName := agent.Metadata.Name
	if problems := k8svalidation.IsDNS1123Label(agentName); len(problems) > 0 {
		return nil, fmt.Errorf("%w: agent name %q must be a DNS label to name a SPIFFE ID: %s",
			errInvalidTarget, agentName, strings.Join(problems, "; "))
	}
	uid := in.Deployment.Metadata.UID
	if problems := k8svalidation.IsValidLabelValue(uid); uid == "" || len(problems) > 0 {
		return nil, fmt.Errorf("%w: Deployment %q has no usable UID %q; its SPIFFE IDs would not be unique",
			errInvalidTarget, in.Deployment.Metadata.Name, uid)
	}
	env, err := workloadEnv(in, rcfg, org, agentName)
	if err != nil {
		return nil, err
	}

	name := workloadName(in.Deployment)
	selector := map[string]string{workloadLabel: name}
	labels := map[string]string{managedByLabel: managedByValue, workloadLabel: name, agentLabel: agentName, deploymentUIDLabel: uid}
	meta := func() metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: maps.Clone(labels)}
	}
	noToken := false
	replicas := dcfg.replicas()

	serviceAccount := &corev1.ServiceAccount{ObjectMeta: meta(), AutomountServiceAccountToken: &noToken}
	deployment := &appsv1.Deployment{
		ObjectMeta: meta(),
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: maps.Clone(selector)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: maps.Clone(labels)},
				Spec:       podSpec(name, strings.TrimSpace(agent.Spec.Source.Image), env, dcfg),
			},
		},
	}
	return &workload{
		namespace:      namespace,
		name:           name,
		org:            org,
		agent:          agentName,
		actorSubject:   rcfg.agentIDPrefix(org, agentName, uid),
		serviceAccount: serviceAccount,
		deployment:     deployment,
		networkPolicy:  networkPolicy(meta(), selector, rcfg.Gateway),
	}, nil
}

func workloadEnv(in types.ApplyInput, rcfg runtimeConfig, org, agent string) ([]corev1.EnvVar, error) {
	keys := make([]string, 0, len(in.Deployment.Spec.Env))
	for key := range in.Deployment.Spec.Env {
		if slices.Contains(reservedEnv, key) {
			return nil, fmt.Errorf("%w: env %s is set by the runtime", errInvalidTarget, key)
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	env := []corev1.EnvVar{
		{Name: envSPIFFESocket, Value: "unix://" + spiffeMountPath + "/spire-agent.sock"},
		{Name: envGatewayURL, Value: rcfg.Gateway.URL},
		{Name: envGatewaySPIFFEID, Value: rcfg.Gateway.SPIFFEID},
		{Name: envGatewayAudience, Value: rcfg.Gateway.Audience},
		{Name: envTemporalAddress, Value: rcfg.Temporal.Address},
		{Name: envOrg, Value: org},
		{Name: envAgent, Value: agent},
	}
	if endpoint := strings.TrimSpace(in.Runtime.Spec.TelemetryEndpoint); endpoint != "" {
		env = append(env, corev1.EnvVar{Name: envOTLPEndpoint, Value: endpoint})
	}
	for _, key := range keys {
		env = append(env, corev1.EnvVar{Name: key, Value: in.Deployment.Spec.Env[key]})
	}
	return env, nil
}

// podSpec runs the agent image under Pod Security "restricted", with the
// SPIFFE Workload API mounted and no Kubernetes API token.
func podSpec(serviceAccount, image string, env []corev1.EnvVar, dcfg deployConfig) corev1.PodSpec {
	noToken, yes, no, readOnly := false, true, false, true
	return corev1.PodSpec{
		ServiceAccountName:           serviceAccount,
		AutomountServiceAccountToken: &noToken,
		EnableServiceLinks:           &no,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   &yes,
			RunAsUser:      dcfg.RunAsUser,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:    containerName,
			Image:   image,
			Command: slices.Clone(dcfg.Command),
			Args:    slices.Clone(dcfg.Args),
			Env:     env,
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: &no,
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
			VolumeMounts: []corev1.VolumeMount{{Name: spiffeVolume, MountPath: spiffeMountPath, ReadOnly: true}},
		}},
		Volumes: []corev1.Volume{{
			Name: spiffeVolume,
			VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{
				Driver:   spiffeCSIDriver,
				ReadOnly: &readOnly,
			}},
		}},
	}
}

// networkPolicy admits no ingress and lets the pods reach only the gateway's
// pods and cluster DNS. The SPIFFE Workload API is a local socket, not a
// network destination.
func networkPolicy(meta metav1.ObjectMeta, selector map[string]string, gateway gatewayConfig) *networkingv1.NetworkPolicy {
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
	dns := intstr.FromInt32(53)
	return &networkingv1.NetworkPolicy{
		ObjectMeta: meta,
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: maps.Clone(selector)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": gateway.Namespace}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: maps.Clone(gateway.PodLabels)},
				}}},
				{
					To: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &dns}, {Protocol: &tcp, Port: &dns}},
				},
			},
		},
	}
}
