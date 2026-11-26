package agentgateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

func testConfig() Config {
	return Config{
		Namespace: "gw", Gateway: "gateway", Listener: "https-agents",
		GuardrailService: "extauth-bridge", GuardrailPort: 9000,
		OpenBaoSVIDHeader: "X-Openbao-SVID", OpenBaoAuthMount: "jwt-spiffe",
	}
}

func server(namespace, name, tag, url, transport string) *v1alpha1.MCPServer {
	return &v1alpha1.MCPServer{
		Metadata: v1alpha1.ObjectMeta{Namespace: namespace, Name: name, Tag: tag},
		Spec:     v1alpha1.MCPServerSpec{Remote: &v1alpha1.MCPRemote{Type: transport, URL: url}},
	}
}

func static(t *testing.T, backend *unstructured.Unstructured) map[string]any {
	t.Helper()
	targets, _, _ := unstructured.NestedSlice(backend.Object, "spec", "mcp", "targets")
	require.Len(t, targets, 1)
	s, ok := targets[0].(map[string]any)["static"].(map[string]any)
	require.True(t, ok)
	return s
}

func TestBuildTarget(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		transport string
		want      map[string]any
		wantErr   bool
	}{
		{"https default port", "https://mcp.example.com/mcp", "streamable-http",
			map[string]any{"host": "mcp.example.com", "port": int64(443), "path": "/mcp", "protocol": "StreamableHTTP",
				"policies": map[string]any{"tls": map[string]any{"sni": "mcp.example.com"}}}, false},
		{"http explicit port, no path", "http://svc.ns.svc:8765", "streamable-http",
			map[string]any{"host": "svc.ns.svc", "port": int64(8765), "protocol": "StreamableHTTP"}, false},
		{"sse over https on an IP: no SNI", "https://10.0.0.5:8443/sse", "SSE",
			map[string]any{"host": "10.0.0.5", "port": int64(8443), "path": "/sse", "protocol": "SSE",
				"policies": map[string]any{"tls": map[string]any{}}}, false},
		{"unknown transport", "https://x.example/mcp", "stdio", nil, true},
		{"user info", "https://u:p@x.example/mcp", "streamable-http", nil, true},
		{"query", "https://x.example/mcp?k=v", "streamable-http", nil, true},
		{"not http", "ftp://x.example/mcp", "streamable-http", nil, true},
		{"bad port", "https://x.example:99999/mcp", "streamable-http", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects, err := Build(testConfig(), server("team", "crm", "1.0.0", tt.url, tt.transport), nil)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, errUnsupportedRemote)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, static(t, objects[0]))
		})
	}
}

func TestBuildRefusesStaticHeaders(t *testing.T) {
	s := server("team", "crm", "1.0.0", "https://x.example/mcp", "streamable-http")
	s.Spec.Remote.Headers = []v1alpha1.HTTPHeader{{Name: "Authorization", Value: "Bearer secret"}}
	_, err := Build(testConfig(), s, nil)
	require.ErrorIs(t, err, errUnsupportedRemote)
}

func TestBuildObjects(t *testing.T) {
	cfg := testConfig()
	objects, err := Build(cfg, server("team", "CRM Tools", "1.0.0", "https://crm.example/mcp", "streamable-http"), &Credential{
		Type: v1alpha1.MCPCredentialTypeStatic,
		Org:  "org-team", Role: "mcp-crm-tools-abc", Path: "agentregistry/data/secrets/crm-key", Key: "token",
		Header: "Authorization", Scheme: "Bearer",
	})
	require.NoError(t, err)
	require.Len(t, objects, 3)
	backend, route, policy := objects[0], objects[1], objects[2]
	name := ObjectName("team", "CRM Tools", "1.0.0")
	assert.Regexp(t, `^mcp-crm-tools-[0-9a-f]{12}$`, name)
	for i, gvk := range Kinds {
		assert.Equal(t, gvk, objects[i].GroupVersionKind())
		assert.Equal(t, "gw", objects[i].GetNamespace())
		assert.Equal(t, name, objects[i].GetName())
		assert.Equal(t, "agentregistry", objects[i].GetLabels()[managedByLabel])
		assert.Equal(t, "team/CRM Tools:1.0.0", objects[i].GetAnnotations()[sourceAnnotation])
	}
	assert.Equal(t, "crm.example", static(t, backend)["host"])

	parent, _, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	assert.Equal(t, map[string]any{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "gateway", "sectionName": "https-agents"}, parent[0])
	rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	rule := rules[0].(map[string]any)
	assert.Equal(t, "/mcp/team/CRM%20Tools/1.0.0", rule["matches"].([]any)[0].(map[string]any)["path"].(map[string]any)["value"])
	assert.Equal(t, name, rule["backendRefs"].([]any)[0].(map[string]any)["name"])

	_, hasTraffic := policy.Object["spec"].(map[string]any)["traffic"]
	assert.False(t, hasTraffic, "the listener's identity policy authenticates the agent, not the route")
	processors, _, _ := unstructured.NestedSlice(policy.Object, "spec", "backend", "mcp", "guardrails", "processors")
	proc := processors[0].(map[string]any)
	assert.Equal(t, map[string]any{
		"*": "Request", "tools/list": "Full",
		"resources/subscribe": "Response", "resources/unsubscribe": "Response", "completion/complete": "Response",
	}, proc["methods"], "every method goes to the PDP, in the phase agentgateway runs for it")
	remote := proc["remote"].(map[string]any)
	assert.Equal(t, "FailClosed", remote["failureMode"])
	assert.Equal(t, []any{
		"x-agentregistry-agent", "x-agentregistry-deployment", "x-agentregistry-deployment-uid", "x-agentregistry-spiffe-id",
		"x-openbao-svid",
	}, remote["allowedRequestHeaders"], "the resolved identity and the SVID for OpenBao, nothing else")
	assert.Equal(t, map[string]any{
		"claims":                "jwt",
		"spiffe_id":             `request.headers["x-agentregistry-spiffe-id"]`,
		"agent":                 `request.headers["x-agentregistry-agent"]`,
		"resource_id":           `"team/CRM Tools@1.0.0"`,
		"credential_type":       `"Static"`,
		"credential_org":        `"org-team"`,
		"credential_auth_mount": `"jwt-spiffe"`,
		"credential_role":       `"mcp-crm-tools-abc"`,
		"credential_path":       `"agentregistry/data/secrets/crm-key"`,
		"credential_key":        `"token"`,
		"credential_header":     `"Authorization"`,
		"credential_scheme":     `"Bearer"`,
		"openbao_svid_header":   `"x-openbao-svid"`,
	}, remote["metadata"])
}

func TestBuildWithoutCredential(t *testing.T) {
	objects, err := Build(testConfig(), server("team", "crm", "1.0.0", "https://crm.example/mcp", "streamable-http"), nil)
	require.NoError(t, err)
	metadata, _, _ := unstructured.NestedMap(objects[2].Object, "spec", "backend", "mcp", "guardrails")
	remote := metadata["processors"].([]any)[0].(map[string]any)["remote"].(map[string]any)
	assert.Equal(t, map[string]any{
		"claims": "jwt", "spiffe_id": `request.headers["x-agentregistry-spiffe-id"]`, "agent": `request.headers["x-agentregistry-agent"]`,
		"resource_id": `"team/crm@1.0.0"`, "openbao_svid_header": `"x-openbao-svid"`,
	},
		remote["metadata"], "the SVID header is named even without a credential, so it is always removed")
}

func TestBuildOAuthCredential(t *testing.T) {
	objects, err := Build(testConfig(), server("team", "crm", "1.0.0", "https://crm.example/mcp", "streamable-http"), &Credential{
		Type: v1alpha1.MCPCredentialTypeOAuthClientCredentials,
		Org:  "org-team", Role: "mcp-crm-abc", Path: "agentregistry/data/secrets/crm-client",
		Header: "Authorization", Scheme: "Bearer",
		OAuth: &OAuthClient{
			TokenURL: "https://auth.example/token", ClientIDKey: "client-id", ClientSecretKey: "client-secret",
			Scope: "crm:read crm:write", Resource: "https://crm.example/mcp",
		},
	})
	require.NoError(t, err)
	processors, _, _ := unstructured.NestedSlice(objects[2].Object, "spec", "backend", "mcp", "guardrails", "processors")
	metadata := processors[0].(map[string]any)["remote"].(map[string]any)["metadata"].(map[string]any)
	assert.Equal(t, map[string]any{
		"claims":                       "jwt",
		"spiffe_id":                    `request.headers["x-agentregistry-spiffe-id"]`,
		"agent":                        `request.headers["x-agentregistry-agent"]`,
		"resource_id":                  `"team/crm@1.0.0"`,
		"openbao_svid_header":          `"x-openbao-svid"`,
		"credential_type":              `"OAuthClientCredentials"`,
		"credential_org":               `"org-team"`,
		"credential_auth_mount":        `"jwt-spiffe"`,
		"credential_role":              `"mcp-crm-abc"`,
		"credential_path":              `"agentregistry/data/secrets/crm-client"`,
		"credential_header":            `"Authorization"`,
		"credential_scheme":            `"Bearer"`,
		"credential_token_url":         `"https://auth.example/token"`,
		"credential_client_id_key":     `"client-id"`,
		"credential_client_secret_key": `"client-secret"`,
		"credential_scope":             `"crm:read crm:write"`,
		"credential_resource":          `"https://crm.example/mcp"`,
	}, metadata, "no credential_key: the token is got with the client's identifier and secret")
}

func TestCanonicalResource(t *testing.T) {
	tests := []struct {
		url, want string
		wantErr   bool
	}{
		{"https://crm.example/mcp", "https://crm.example/mcp", false},
		{"https://crm.example/mcp/", "https://crm.example/mcp", false},
		{"https://crm.example/", "https://crm.example", false},
		{"HTTPS://CRM.Example:8443/MCP", "https://crm.example:8443/MCP", false},
		{"http://svc.ns.svc:8765/mcp", "http://svc.ns.svc:8765/mcp", false},
		{"https://crm.example/mcp?x=1", "", true},
		{"https://crm.example/mcp#a", "", true},
		{"crm.example/mcp", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got, err := CanonicalResource(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestObjectNameIsUniquePerVersion(t *testing.T) {
	a := ObjectName("team", "crm", "1.0.0")
	assert.NotEqual(t, a, ObjectName("team", "crm", "1.0.1"))
	assert.NotEqual(t, a, ObjectName("other", "crm", "1.0.0"))
	assert.Regexp(t, `^mcp-[0-9a-f]{12}$`, ObjectName("team", "!!!", "1"))
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no namespace", func(c *Config) { c.Namespace = "" }},
		{"bad gateway name", func(c *Config) { c.Gateway = "Not_A_Name" }},
		{"port out of range", func(c *Config) { c.GuardrailPort = 0 }},
		{"bad header", func(c *Config) { c.OpenBaoSVIDHeader = "x svid" }},
		{"no auth mount", func(c *Config) { c.OpenBaoAuthMount = "/" }},
	}
	require.NoError(t, testConfig().Validate())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testConfig()
			tt.mutate(&c)
			assert.Error(t, c.Validate())
		})
	}
}
