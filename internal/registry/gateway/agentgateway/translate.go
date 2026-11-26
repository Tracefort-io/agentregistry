package agentgateway

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/agentregistry-dev/agentregistry/internal/registry/workloadidentity"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

// The kinds this package writes.
var (
	BackendGVK   = schema.GroupVersionKind{Group: "agentgateway.dev", Version: "v1alpha1", Kind: "AgentgatewayBackend"}
	PolicyGVK    = schema.GroupVersionKind{Group: "agentgateway.dev", Version: "v1alpha1", Kind: "AgentgatewayPolicy"}
	HTTPRouteGVK = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	// Kinds lists them in the order they are written; removal goes in
	// reverse, so a route never points at a missing backend.
	Kinds = []schema.GroupVersionKind{BackendGVK, HTTPRouteGVK, PolicyGVK}
)

// Labels and annotations on every generated object.
const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "agentregistry"
	componentLabel = "app.kubernetes.io/component"
	componentValue = "mcp-gateway"
	// sourceAnnotation records the MCPServer version an object serves.
	sourceAnnotation = "agentregistry.dev/mcp-server"
)

// Selector selects the objects this package manages.
var Selector = managedByLabel + "=" + managedByValue + "," + componentLabel + "=" + componentValue

// Keys of the guardrail callout's metadata. claims and resource_id identify
// the caller and the server; openbao_svid_header names the header the
// callout removes from every upstream request, so no server ever receives an
// agent's SVID for OpenBao. The credential_* keys are set only for a server
// with spec.credential; credential_key only for a Static one, the OAuth keys
// only for an OAuthClientCredentials one.
const (
	metaClaims                    = "claims"
	metaSPIFFEID                  = "spiffe_id"
	metaAgent                     = "agent"
	metaResourceID                = "resource_id"
	metaSVIDHeader                = "openbao_svid_header"
	metaCredentialType            = "credential_type"
	metaCredentialOrg             = "credential_org"
	metaCredentialMount           = "credential_auth_mount"
	metaCredentialRole            = "credential_role"
	metaCredentialPath            = "credential_path"
	metaCredentialKey             = "credential_key"
	metaCredentialHeader          = "credential_header"
	metaCredentialScheme          = "credential_scheme"
	metaCredentialTokenURL        = "credential_token_url"
	metaCredentialClientIDKey     = "credential_client_id_key"
	metaCredentialClientSecretKey = "credential_client_secret_key"
	metaCredentialScope           = "credential_scope"
	metaCredentialResource        = "credential_resource"
)

var errUnsupportedRemote = errors.New("unsupported remote")

// Credential says where the guardrail callout fetches a server's credential
// and how the gateway sends it.
type Credential struct {
	// Type is the MCPCredential type.
	Type v1alpha1.MCPCredentialType
	// Org is the OpenBao namespace; Role is the grant's role of the JWT auth
	// method; Path is the KV v2 data path; Key the field holding a Static
	// value.
	Org, Role, Path, Key string
	// Header carries the value upstream, after Scheme when set.
	Header, Scheme string
	// OAuth is set for type OAuthClientCredentials.
	OAuth *OAuthClient
}

// OAuthClient says how the callout gets an access token with the server's
// OAuth client, whose identifier and secret are the Secret's keys
// ClientIDKey and ClientSecretKey.
type OAuthClient struct {
	TokenURL, ClientIDKey, ClientSecretKey string
	// Scope is the space-separated scope requested, empty for none.
	Scope string
	// Resource is the RFC 8707 resource indicator.
	Resource string
}

var invalidNameChars = regexp.MustCompile(`[^a-z0-9]+`)

// ObjectName names the three objects of one MCPServer version: readable, and
// unique for (namespace, name, tag) whatever the names hold.
func ObjectName(namespace, name, tag string) string {
	readable := strings.Trim(invalidNameChars.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(readable) > 30 {
		readable = strings.TrimRight(readable[:30], "-")
	}
	digest := sha256.Sum256([]byte(namespace + "/" + name + "/" + tag))
	if readable == "" {
		return fmt.Sprintf("mcp-%x", digest[:6])
	}
	return fmt.Sprintf("mcp-%s-%x", readable, digest[:6])
}

// RoutePath is where agents reach one MCPServer version on the gateway.
func RoutePath(namespace, name, tag string) string {
	return "/mcp/" + url.PathEscape(namespace) + "/" + url.PathEscape(name) + "/" + url.PathEscape(tag)
}

// ResourceID identifies the server to the PDP (context.mcp_server).
func ResourceID(namespace, name, tag string) string {
	return namespace + "/" + name + "@" + tag
}

// Build returns the backend, route and policy for one MCPServer version
// with spec.remote; cred is nil for a server without a credential.
func Build(cfg Config, server *v1alpha1.MCPServer, cred *Credential) ([]*unstructured.Unstructured, error) {
	if server.Spec.Remote == nil {
		return nil, fmt.Errorf("%w: MCPServer has no spec.remote", errUnsupportedRemote)
	}
	namespace, name, tag := server.Metadata.NamespaceOrDefault(), server.Metadata.Name, server.Metadata.Tag
	target, err := mcpTarget(server.Spec.Remote)
	if err != nil {
		return nil, err
	}
	objectName := ObjectName(namespace, name, tag)
	source := namespace + "/" + name + ":" + tag

	backend := newObject(BackendGVK, cfg.Namespace, objectName, source)
	backend.Object["spec"] = map[string]any{
		"mcp": map[string]any{"targets": []any{target}},
	}

	route := newObject(HTTPRouteGVK, cfg.Namespace, objectName, source)
	route.Object["spec"] = map[string]any{
		"parentRefs": []any{map[string]any{
			"group": "gateway.networking.k8s.io", "kind": "Gateway",
			"name": cfg.Gateway, "sectionName": cfg.Listener,
		}},
		"rules": []any{map[string]any{
			"matches": []any{map[string]any{
				"path": map[string]any{"type": "PathPrefix", "value": RoutePath(namespace, name, tag)},
			}},
			"backendRefs": []any{map[string]any{
				"group": BackendGVK.Group, "kind": BackendGVK.Kind, "name": objectName,
			}},
		}},
	}

	metadata := map[string]any{
		metaClaims: "jwt",
		// The identity the listener's identity check resolved; the gateway
		// set these headers, replacing any the agent sent.
		metaSPIFFEID:   celHeader(workloadidentity.HeaderSPIFFEID),
		metaAgent:      celHeader(workloadidentity.HeaderAgent),
		metaResourceID: celString(ResourceID(namespace, name, tag)),
		metaSVIDHeader: celString(strings.ToLower(cfg.OpenBaoSVIDHeader)),
	}
	if cred != nil {
		metadata[metaCredentialType] = celString(string(cred.Type))
		metadata[metaCredentialOrg] = celString(cred.Org)
		metadata[metaCredentialMount] = celString(strings.Trim(cfg.OpenBaoAuthMount, "/"))
		metadata[metaCredentialRole] = celString(cred.Role)
		metadata[metaCredentialPath] = celString(cred.Path)
		metadata[metaCredentialHeader] = celString(cred.Header)
		metadata[metaCredentialScheme] = celString(cred.Scheme)
		if cred.OAuth != nil {
			metadata[metaCredentialTokenURL] = celString(cred.OAuth.TokenURL)
			metadata[metaCredentialClientIDKey] = celString(cred.OAuth.ClientIDKey)
			metadata[metaCredentialClientSecretKey] = celString(cred.OAuth.ClientSecretKey)
			metadata[metaCredentialScope] = celString(cred.OAuth.Scope)
			metadata[metaCredentialResource] = celString(cred.OAuth.Resource)
		} else {
			metadata[metaCredentialKey] = celString(cred.Key)
		}
	}
	policy := newObject(PolicyGVK, cfg.Namespace, objectName, source)
	policy.Object["spec"] = map[string]any{
		"targetRefs": []any{map[string]any{
			"group": HTTPRouteGVK.Group, "kind": HTTPRouteGVK.Kind, "name": objectName,
		}},
		"backend": map[string]any{
			"mcp": map[string]any{"guardrails": map[string]any{"processors": []any{map[string]any{
				// Every method is sent to the PDP: in the request phase,
				// tools/list also on the way back to filter the list, and
				// the methods agentgateway runs only in the response phase
				// there.
				"methods": guardrailMethods(),
				"remote": map[string]any{
					"backendRef": map[string]any{
						"group": "", "kind": "Service",
						"name": cfg.GuardrailService, "port": int64(cfg.GuardrailPort),
					},
					"failureMode": "FailClosed",
					"metadata":    metadata,
					// The callout sees only the identity the listener's
					// identity check resolved (set by the gateway, replacing
					// any the agent sent) and the agent's SVID for OpenBao.
					"allowedRequestHeaders": calloutHeaders(cfg),
				},
			}}}},
		},
	}
	return []*unstructured.Unstructured{backend, route, policy}, nil
}

// mcpTarget translates spec.remote into a static MCP target.
func mcpTarget(remote *v1alpha1.MCPRemote) (map[string]any, error) {
	var protocol string
	switch strings.ToLower(strings.TrimSpace(remote.Type)) {
	case "streamable-http", "http":
		protocol = "StreamableHTTP"
	case "sse":
		protocol = "SSE"
	default:
		return nil, fmt.Errorf("%w: transport %q (want streamable-http or sse)", errUnsupportedRemote, remote.Type)
	}
	if len(remote.Headers) > 0 {
		// Static headers would put a credential in the registry record and
		// in the gateway config; spec.credential is the way to send one.
		return nil, fmt.Errorf("%w: spec.remote.headers is not supported; use spec.credential", errUnsupportedRemote)
	}
	u, err := url.Parse(remote.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%w: url %q must be an http or https URL", errUnsupportedRemote, remote.URL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: url %q must not carry user info, a query or a fragment", errUnsupportedRemote, remote.URL)
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%w: url %q has an invalid port", errUnsupportedRemote, remote.URL)
		}
	}
	static := map[string]any{"host": u.Hostname(), "port": int64(port), "protocol": protocol}
	if u.Path != "" && u.Path != "/" {
		static["path"] = u.Path
	}
	if u.Scheme == "https" {
		tls := map[string]any{}
		if net.ParseIP(u.Hostname()) == nil {
			tls["sni"] = u.Hostname()
		}
		static["policies"] = map[string]any{"tls": tls}
	}
	return map[string]any{"name": "upstream", "static": static}, nil
}

// CanonicalResource is the canonical URI of an MCP server at rawURL, the
// resource indicator the MCP authorization specification requires in token
// requests: lowercase scheme and host, no trailing slash.
func CanonicalResource(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("%w: url %q must be an http or https URL", errUnsupportedRemote, rawURL)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%w: url %q must not carry user info, a query or a fragment", errUnsupportedRemote, rawURL)
	}
	canonical := url.URL{Scheme: strings.ToLower(u.Scheme), Host: strings.ToLower(u.Host), Path: strings.TrimRight(u.Path, "/"), RawPath: strings.TrimRight(u.RawPath, "/")}
	return canonical.String(), nil
}

func newObject(gvk schema.GroupVersionKind, namespace, name, source string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	obj.SetGroupVersionKind(gvk)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	obj.SetLabels(map[string]string{managedByLabel: managedByValue, componentLabel: componentValue})
	obj.SetAnnotations(map[string]string{sourceAnnotation: source})
	return obj
}

// guardrailMethods routes every MCP method to the guardrail callout, in the
// phases agentgateway runs for it: resources/subscribe,
// resources/unsubscribe and completion/complete have only a response phase
// (agentgateway warns that a request phase does not run for them).
func guardrailMethods() map[string]any {
	return map[string]any{
		"*":                     "Request",
		"tools/list":            "Full",
		"resources/subscribe":   "Response",
		"resources/unsubscribe": "Response",
		"completion/complete":   "Response",
	}
}

// celHeader is a CEL expression for the request header name.
func celHeader(name string) string {
	return "request.headers[" + celString(strings.ToLower(name)) + "]"
}

// calloutHeaders are the request headers the guardrail callout receives.
func calloutHeaders(cfg Config) []any {
	headers := make([]any, 0, len(workloadidentity.ResponseHeaders)+1)
	for _, h := range workloadidentity.ResponseHeaders {
		headers = append(headers, strings.ToLower(h))
	}
	return append(headers, strings.ToLower(cfg.OpenBaoSVIDHeader))
}

// celString is a CEL string literal of s.
func celString(s string) string {
	return strconv.Quote(s)
}
