package credentialgrants

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/secret/openbao"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

type fakeOrg struct {
	policies map[string]string
	roles    map[string]openbao.GrantRole
}

type fakeWriter struct {
	orgs map[string]*fakeOrg
}

func newFakeWriter(orgs ...string) *fakeWriter {
	w := &fakeWriter{orgs: map[string]*fakeOrg{}}
	for _, org := range orgs {
		w.org(org)
	}
	return w
}

func (w *fakeWriter) org(name string) *fakeOrg {
	if w.orgs[name] == nil {
		w.orgs[name] = &fakeOrg{policies: map[string]string{}, roles: map[string]openbao.GrantRole{}}
	}
	return w.orgs[name]
}

func (w *fakeWriter) PutPolicy(_ context.Context, org, name, hcl string) error {
	w.org(org).policies[name] = hcl
	return nil
}
func (w *fakeWriter) DeletePolicy(_ context.Context, org, name string) error {
	delete(w.org(org).policies, name)
	return nil
}
func (w *fakeWriter) PutRole(_ context.Context, org, name string, role openbao.GrantRole) error {
	w.org(org).roles[name] = role
	return nil
}
func (w *fakeWriter) DeleteRole(_ context.Context, org, name string) error {
	delete(w.org(org).roles, name)
	return nil
}
func (w *fakeWriter) ListRoles(_ context.Context, org string) ([]string, error) {
	var names []string
	for name := range w.org(org).roles {
		if strings.HasPrefix(name, openbao.NamePrefix) {
			names = append(names, name)
		}
	}
	return names, nil
}
func (w *fakeWriter) ListPolicies(_ context.Context, org string) ([]string, error) {
	var names []string
	for name := range w.org(org).policies {
		if strings.HasPrefix(name, openbao.NamePrefix) {
			names = append(names, name)
		}
	}
	return names, nil
}
func (w *fakeWriter) ListOrgs(_ context.Context, prefix string) ([]string, error) {
	var names []string
	for name := range w.orgs {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

type fakeLocator struct{}

func (fakeLocator) OrgNamespace(namespace string) string { return "org-" + namespace }
func (fakeLocator) PayloadPath(_, name string) (string, error) {
	return "agentregistry/data/secrets/" + name, nil
}

type world struct {
	deployments []*types.DeploymentRecord
	objects     map[string]v1alpha1.Object // kind/namespace/name
	revoked     map[string]bool
}

func (w *world) getter(_ context.Context, ref v1alpha1.ResourceRef) (v1alpha1.Object, error) {
	if o, ok := w.objects[ref.Kind+"/"+ref.Namespace+"/"+ref.Name]; ok {
		return o, nil
	}
	return nil, errors.New("not found")
}

func (w *world) agent(namespace, name string, servers ...v1alpha1.ResourceRef) {
	w.objects[v1alpha1.KindAgent+"/"+namespace+"/"+name] = &v1alpha1.Agent{
		Metadata: v1alpha1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:     v1alpha1.AgentSpec{MCPServers: servers},
	}
}

func (w *world) server(namespace, name, secret string) {
	s := &v1alpha1.MCPServer{Metadata: v1alpha1.ObjectMeta{Namespace: namespace, Name: name}}
	if secret != "" {
		s.Spec.Credential = &v1alpha1.MCPCredential{SecretRef: v1alpha1.SecretKeyRef{Name: secret, Key: "token"}}
	}
	w.objects[v1alpha1.KindMCPServer+"/"+namespace+"/"+name] = s
}

func (w *world) deployment(namespace, name, agent, prefix string) *types.DeploymentRecord {
	d := &types.DeploymentRecord{
		Deployment: &v1alpha1.Deployment{
			Metadata: v1alpha1.ObjectMeta{Namespace: namespace, Name: name},
			Spec:     v1alpha1.DeploymentSpec{TargetRef: v1alpha1.ResourceRef{Kind: v1alpha1.KindAgent, Name: agent}},
		},
		InternalMeta: types.DeploymentInternalMeta{ActorSubject: prefix},
	}
	w.deployments = append(w.deployments, d)
	return d
}

func (w *world) reconciler(t *testing.T, writer Writer) *Reconciler {
	t.Helper()
	r, err := New(writer, fakeLocator{},
		func(context.Context) ([]*types.DeploymentRecord, error) { return w.deployments, nil },
		func(_ context.Context, prefixes []string) (map[string]bool, error) {
			out := map[string]bool{}
			for _, p := range prefixes {
				out[p] = w.revoked[p]
			}
			return out, nil
		},
		w.getter, Config{OrgPrefix: "org-"})
	require.NoError(t, err)
	return r
}

const (
	prefixA = "spiffe://td/org/default/agent/credit/deployment/a/"
	prefixB = "spiffe://td/org/default/agent/credit/deployment/b/"
	prefixC = "spiffe://td/org/default/agent/fraud/deployment/c/"
)

func newWorld() *world {
	w := &world{objects: map[string]v1alpha1.Object{}, revoked: map[string]bool{}}
	w.server("default", "crm", "crm-api")
	w.server("default", "docs", "") // no credential
	w.server("other", "payments", "pay-api")
	w.agent("default", "credit", v1alpha1.ResourceRef{Name: "crm"}, v1alpha1.ResourceRef{Name: "docs"},
		v1alpha1.ResourceRef{Name: "payments", Namespace: "other"})
	w.agent("default", "fraud", v1alpha1.ResourceRef{Name: "docs"})
	w.deployment("default", "desk-a", "credit", prefixA)
	w.deployment("default", "desk-b", "credit", prefixB)
	w.deployment("default", "fraud", "fraud", prefixC)
	return w
}

func TestSyncGrantsEachCredentialToTheAgentsThatListIt(t *testing.T) {
	w := newWorld()
	writer := newFakeWriter()
	require.NoError(t, w.reconciler(t, writer).Sync(context.Background()))

	name := GrantName("default", "crm", "crm-api")
	org := writer.orgs["org-default"]
	require.NotNil(t, org)
	assert.Equal(t, []string{name}, keys(org.roles), "only the server with a credential gets a grant")
	assert.Equal(t, "path \"agentregistry/data/secrets/crm-api\" {\n  capabilities = [\"read\"]\n}\n", org.policies[name])

	role := org.roles[name]
	assert.Equal(t, []string{prefixA + "*", prefixB + "*"}, role.SubjectGlobs, "every Deployment of the agent, none of fraud's")
	assert.Equal(t, "openbao", role.Audience)
	assert.Equal(t, name, role.Policy)
	assert.Equal(t, 60, role.TTLSeconds)
	assert.Equal(t, 1, role.NumUses, "one read per login")

	assert.Nil(t, writer.orgs["org-other"], "no grant across orgs")
}

func TestSyncGrantsOAuthClientCredentialsLikeAnyCredential(t *testing.T) {
	w := newWorld()
	crm := w.objects[v1alpha1.KindMCPServer+"/default/crm"].(*v1alpha1.MCPServer)
	crm.Spec.Credential = &v1alpha1.MCPCredential{
		Type:      v1alpha1.MCPCredentialTypeOAuthClientCredentials,
		SecretRef: v1alpha1.SecretKeyRef{Name: "crm-api"},
		OAuthClientCredentials: &v1alpha1.MCPOAuthClientCredentials{
			TokenURL: "https://auth.example/token", ClientIDKey: "id", ClientSecretKey: "secret",
		},
	}
	writer := newFakeWriter()
	require.NoError(t, w.reconciler(t, writer).Sync(context.Background()))

	name := GrantName("default", "crm", "crm-api")
	org := writer.orgs["org-default"]
	require.NotNil(t, org)
	assert.Equal(t, "path \"agentregistry/data/secrets/crm-api\" {\n  capabilities = [\"read\"]\n}\n", org.policies[name],
		"the client's identifier and secret are read together, once per login")
	assert.Equal(t, []string{prefixA + "*", prefixB + "*"}, org.roles[name].SubjectGlobs)
	assert.Equal(t, 1, org.roles[name].NumUses)
}

func TestSyncExcludesRevokedTerminatingAndDiscovered(t *testing.T) {
	w := newWorld()
	w.revoked[prefixA] = true
	now := time.Now()
	w.deployments[1].Metadata.DeletionTimestamp = &now
	discovered := w.deployment("default", "seen", "credit", "spiffe://td/org/default/agent/credit/deployment/seen/")
	discovered.Metadata.Annotations = map[string]string{v1alpha1.DeploymentOriginAnnotation: v1alpha1.DeploymentOriginDiscovered}

	writer := newFakeWriter("org-default")
	require.NoError(t, w.reconciler(t, writer).Sync(context.Background()))
	assert.Empty(t, writer.orgs["org-default"].roles, "a revoked identity, a Deployment being deleted and an observation get nothing")
	assert.Empty(t, writer.orgs["org-default"].policies)
}

func TestSyncRemovesStaleGrantsOnly(t *testing.T) {
	w := newWorld()
	writer := newFakeWriter("org-default")
	org := writer.orgs["org-default"]
	org.roles["mcp-gone-0123"] = openbao.GrantRole{Policy: "mcp-gone-0123"}
	org.policies["mcp-gone-0123"] = "old"
	org.policies["platform-admin"] = "not ours"

	require.NoError(t, w.reconciler(t, writer).Sync(context.Background()))
	assert.NotContains(t, org.roles, "mcp-gone-0123")
	assert.NotContains(t, org.policies, "mcp-gone-0123")
	assert.Equal(t, "not ours", org.policies["platform-admin"], "only names Grants manages are removed")
	assert.Contains(t, org.roles, GrantName("default", "crm", "crm-api"))
}

func TestRevokeWithdrawsOneIdentity(t *testing.T) {
	w := newWorld()
	writer := newFakeWriter()
	r := w.reconciler(t, writer)
	require.NoError(t, r.Sync(context.Background()))
	name := GrantName("default", "crm", "crm-api")

	require.NoError(t, r.Revoke(context.Background(), prefixA))
	assert.Equal(t, []string{prefixB + "*"}, writer.orgs["org-default"].roles[name].SubjectGlobs)

	// Until its revocation is recorded, a later sync would grant A again;
	// once it is, no sync ever does.
	require.NoError(t, r.Sync(context.Background()))
	assert.Contains(t, writer.orgs["org-default"].roles[name].SubjectGlobs, prefixA+"*")
	w.revoked[prefixA] = true
	require.NoError(t, r.Sync(context.Background()))
	assert.Equal(t, []string{prefixB + "*"}, writer.orgs["org-default"].roles[name].SubjectGlobs)

	require.NoError(t, r.Revoke(context.Background(), prefixB))
	assert.NotContains(t, writer.orgs["org-default"].roles, name, "the last identity gone, the role goes")
	assert.NotContains(t, writer.orgs["org-default"].policies, name, "and its policy")
}

func TestGrantName(t *testing.T) {
	a := GrantName("default", "io.github.acme/CRM server", "crm-api")
	assert.Regexp(t, `^mcp-io-github-acme-crm-server-[0-9a-f]{12}$`, a)
	assert.Equal(t, a, GrantName("default", "io.github.acme/CRM server", "crm-api"), "stable")
	assert.NotEqual(t, a, GrantName("default", "io.github.acme/CRM server", "other-key"), "one per credential")
	assert.NotEqual(t, a, GrantName("acme", "io.github.acme/CRM server", "crm-api"), "one per org")
	assert.Regexp(t, `^mcp-[0-9a-f]{12}$`, GrantName("default", "///", "s"))
	assert.LessOrEqual(t, len(GrantName("default", strings.Repeat("x", 200), "s")), 64)
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
