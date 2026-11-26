package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/agentregistry-dev/agentregistry/internal/registry/credentialgrants"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

// fakeClient keeps objects by kind and name, and counts writes.
type fakeClient struct {
	objects map[string]map[string]*unstructured.Unstructured
	applies int
	deletes []string
	listErr error
}

func newFakeClient() *fakeClient {
	return &fakeClient{objects: map[string]map[string]*unstructured.Unstructured{}}
}

func (f *fakeClient) List(_ context.Context, gvk schema.GroupVersionKind, _, _ string) ([]unstructured.Unstructured, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []unstructured.Unstructured
	for _, obj := range f.objects[gvk.Kind] {
		out = append(out, *obj.DeepCopy())
	}
	return out, nil
}

func (f *fakeClient) Apply(_ context.Context, obj *unstructured.Unstructured) error {
	f.applies++
	if f.objects[obj.GetKind()] == nil {
		f.objects[obj.GetKind()] = map[string]*unstructured.Unstructured{}
	}
	f.objects[obj.GetKind()][obj.GetName()] = obj.DeepCopy()
	return nil
}

func (f *fakeClient) Delete(_ context.Context, gvk schema.GroupVersionKind, _, name string) error {
	f.deletes = append(f.deletes, gvk.Kind+"/"+name)
	delete(f.objects[gvk.Kind], name)
	return nil
}

type fakeLocator struct{}

func (fakeLocator) OrgNamespace(ns string) string { return "org-" + ns }
func (fakeLocator) PayloadPath(_, name string) (string, error) {
	if name == "bad/name" {
		return "", errors.New("invalid Secret name")
	}
	return "agentregistry/data/secrets/" + name, nil
}

func listOf(servers ...*v1alpha1.MCPServer) ServerLister {
	return func(context.Context) ([]*v1alpha1.MCPServer, error) { return servers, nil }
}

func TestSyncCreatesUpdatesAndRemoves(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	crm := server("team", "crm", "1.0.0", "https://crm.example/mcp", "streamable-http")
	crm.Spec.Credential = &v1alpha1.MCPCredential{SecretRef: v1alpha1.SecretKeyRef{Name: "crm-key", Key: "token"}, Scheme: "Bearer"}
	bundled := &v1alpha1.MCPServer{Metadata: v1alpha1.ObjectMeta{Namespace: "team", Name: "bundled", Tag: "1"}}
	servers := []*v1alpha1.MCPServer{crm, bundled}
	r, err := New(client, func(context.Context) ([]*v1alpha1.MCPServer, error) { return servers, nil }, fakeLocator{}, testConfig())
	require.NoError(t, err)

	require.NoError(t, r.Sync(ctx))
	name := ObjectName("team", "crm", "1.0.0")
	for _, gvk := range Kinds {
		assert.Contains(t, client.objects[gvk.Kind], name)
	}
	assert.Equal(t, 3, client.applies, "a server without spec.remote gets nothing")
	remote, _, _ := unstructured.NestedSlice(client.objects[PolicyGVK.Kind][name].Object, "spec", "backend", "mcp", "guardrails", "processors")
	metadata := remote[0].(map[string]any)["remote"].(map[string]any)["metadata"].(map[string]any)
	assert.Equal(t, fmt.Sprintf("%q", credentialgrants.GrantName("team", "crm", "crm-key")), metadata["credential_role"],
		"the role the credential grants write")
	assert.Equal(t, `"org-team"`, metadata["credential_org"])

	require.NoError(t, r.Sync(ctx))
	assert.Equal(t, 3, client.applies, "unchanged objects are not rewritten")

	crm.Spec.Remote.URL = "https://crm.example/v2/mcp"
	require.NoError(t, r.Sync(ctx))
	assert.Equal(t, 4, client.applies, "a changed URL rewrites the backend only")
	assert.Equal(t, "/v2/mcp", static(t, client.objects[BackendGVK.Kind][name])["path"])

	servers = nil // the tag was deleted
	require.NoError(t, r.Sync(ctx))
	assert.Equal(t, []string{"AgentgatewayPolicy/" + name, "HTTPRoute/" + name, "AgentgatewayBackend/" + name}, client.deletes,
		"policy and route go before the backend")
}

func TestSyncOAuthCredential(t *testing.T) {
	oauthServer := func(name, url, resource string) *v1alpha1.MCPServer {
		s := server("team", name, "1.0.0", url, "streamable-http")
		s.Spec.Credential = &v1alpha1.MCPCredential{
			Type:      v1alpha1.MCPCredentialTypeOAuthClientCredentials,
			SecretRef: v1alpha1.SecretKeyRef{Name: name + "-client"},
			OAuthClientCredentials: &v1alpha1.MCPOAuthClientCredentials{
				TokenURL: "https://auth.example/token", ClientIDKey: "id", ClientSecretKey: "secret",
				Scopes: []string{"a", "b"}, Resource: resource,
			},
		}
		return s
	}
	defaulted := oauthServer("crm", "https://CRM.example/mcp/", "")
	explicit := oauthServer("erp", "https://erp.example/mcp", "https://erp.example")

	client := newFakeClient()
	r, err := New(client, listOf(defaulted, explicit), fakeLocator{}, testConfig())
	require.NoError(t, err)
	require.NoError(t, r.Sync(context.Background()))

	metadata := func(name string) map[string]any {
		processors, _, _ := unstructured.NestedSlice(client.objects[PolicyGVK.Kind][ObjectName("team", name, "1.0.0")].Object,
			"spec", "backend", "mcp", "guardrails", "processors")
		return processors[0].(map[string]any)["remote"].(map[string]any)["metadata"].(map[string]any)
	}
	crm := metadata("crm")
	assert.Equal(t, `"https://crm.example/mcp"`, crm["credential_resource"], "defaults to the server's canonical URI")
	assert.Equal(t, `"a b"`, crm["credential_scope"])
	assert.Equal(t, fmt.Sprintf("%q", credentialgrants.GrantName("team", "crm", "crm-client")), crm["credential_role"],
		"the same grant as a Static credential of the Secret")
	assert.Equal(t, `"Authorization"`, crm["credential_header"])
	assert.Equal(t, `"Bearer"`, crm["credential_scheme"])
	assert.NotContains(t, crm, "credential_key")
	assert.Equal(t, `"https://erp.example"`, metadata("erp")["credential_resource"], "an explicit resource is kept")
}

func TestSyncSkipsServersItCannotRoute(t *testing.T) {
	ctx := context.Background()
	noLocator := server("team", "a", "1", "https://a.example/mcp", "streamable-http")
	noLocator.Spec.Credential = &v1alpha1.MCPCredential{SecretRef: v1alpha1.SecretKeyRef{Name: "k", Key: "v"}}
	badSecret := server("team", "b", "1", "https://b.example/mcp", "streamable-http")
	badSecret.Spec.Credential = &v1alpha1.MCPCredential{SecretRef: v1alpha1.SecretKeyRef{Name: "bad/name", Key: "v"}}
	badURL := server("team", "c", "1", "ftp://c.example", "streamable-http")
	good := server("team", "d", "1", "https://d.example/mcp", "streamable-http")

	client := newFakeClient()
	r, err := New(client, listOf(noLocator, good), nil, testConfig())
	require.NoError(t, err)
	require.NoError(t, r.Sync(ctx))
	assert.Len(t, client.objects[BackendGVK.Kind], 1, "without org namespaces a credential cannot be fetched: no route")

	client = newFakeClient()
	r, err = New(client, listOf(badSecret, badURL, good), fakeLocator{}, testConfig())
	require.NoError(t, err)
	require.NoError(t, r.Sync(ctx))
	assert.Equal(t, []string{ObjectName("team", "d", "1")}, keys(client.objects[BackendGVK.Kind]))
}

func TestSyncRemovesNothingWhenListingFails(t *testing.T) {
	client := newFakeClient()
	client.listErr = errors.New("forbidden")
	r, err := New(client, listOf(), nil, testConfig())
	require.NoError(t, err)
	require.Error(t, r.Sync(context.Background()))
	assert.Empty(t, client.deletes)
}

func keys(m map[string]*unstructured.Unstructured) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
