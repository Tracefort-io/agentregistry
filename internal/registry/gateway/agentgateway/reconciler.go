package agentgateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/agentregistry-dev/agentregistry/internal/registry/credentialgrants"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
)

var logger = logging.New("mcp-gateway-config")

// specHashAnnotation records the digest of the generated labels,
// annotations and spec, so an unchanged object is not rewritten (the API
// server adds defaults to the stored spec).
const specHashAnnotation = "agentregistry.dev/spec-hash"

// ServerLister lists every live MCPServer version, in every namespace.
type ServerLister func(ctx context.Context) ([]*v1alpha1.MCPServer, error)

// Locator says where a registry namespace's Secrets live in OpenBao
// (openbao.Store with org namespaces).
type Locator interface {
	OrgNamespace(namespace string) string
	PayloadPath(namespace, name string) (string, error)
}

// Reconciler keeps the gateway's MCP objects in step with the registry.
// Syncs run one at a time.
type Reconciler struct {
	client  ObjectClient
	servers ServerLister
	// locator is nil when Secrets are not in OpenBao org namespaces; servers
	// with a credential then get no route, since no credential could be
	// fetched for them.
	locator Locator
	config  Config

	mu   sync.Mutex
	kick chan struct{}
}

// New returns a Reconciler.
func New(client ObjectClient, servers ServerLister, locator Locator, config Config) (*Reconciler, error) {
	if client == nil || servers == nil {
		return nil, errors.New("mcp gateway config: a client and a server lister are required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Reconciler{client: client, servers: servers, locator: locator, config: config, kick: make(chan struct{}, 1)}, nil
}

// Kick asks Run for a sync soon; it never blocks.
func (r *Reconciler) Kick() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Run syncs after each Kick until ctx ends.
func (r *Reconciler) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.kick:
			if err := r.Sync(ctx); err != nil {
				logger.Error("mcp gateway config: sync failed; the next repair pass retries", "error", err)
			}
		}
	}
}

// Sync writes every wanted object that is missing or changed, then removes
// managed objects no longer wanted. It goes on past a failure and returns
// all of them.
func (r *Reconciler) Sync(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	want, err := r.desired(ctx)
	if err != nil {
		return err
	}
	var errs []error
	existing := map[string]map[string]unstructured.Unstructured{}
	for _, gvk := range Kinds {
		items, err := r.client.List(ctx, gvk, r.config.Namespace, Selector)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		existing[gvk.Kind] = map[string]unstructured.Unstructured{}
		for _, item := range items {
			existing[gvk.Kind][item.GetName()] = item
		}
	}
	for _, gvk := range Kinds {
		for _, obj := range want[gvk.Kind] {
			if current, ok := existing[gvk.Kind][obj.GetName()]; ok &&
				current.GetAnnotations()[specHashAnnotation] == obj.GetAnnotations()[specHashAnnotation] {
				continue
			}
			if err := r.client.Apply(ctx, obj); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, gvk := range slices.Backward(Kinds) {
		current, listed := existing[gvk.Kind]
		if !listed {
			continue // listing failed: removing nothing is the safe side
		}
		for name := range current {
			if _, ok := want[gvk.Kind][name]; ok {
				continue
			}
			if err := r.client.Delete(ctx, gvk, r.config.Namespace, name); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// desired builds the wanted objects, by kind and name. A server that cannot
// be routed is logged and left out, so it has no route at all.
func (r *Reconciler) desired(ctx context.Context) (map[string]map[string]*unstructured.Unstructured, error) {
	servers, err := r.servers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list MCP servers: %w", err)
	}
	want := map[string]map[string]*unstructured.Unstructured{}
	for _, gvk := range Kinds {
		want[gvk.Kind] = map[string]*unstructured.Unstructured{}
	}
	for _, server := range servers {
		if server.Spec.Remote == nil {
			continue
		}
		log := logger.With("mcp_server", server.Metadata.NamespaceOrDefault()+"/"+server.Metadata.Name, "tag", server.Metadata.Tag)
		cred, err := r.credential(server)
		if err != nil {
			log.Warn("mcp gateway config: no route for this server", "error", err)
			continue
		}
		objects, err := Build(r.config, server, cred)
		if err != nil {
			log.Warn("mcp gateway config: no route for this server", "error", err)
			continue
		}
		for _, obj := range objects {
			if err := stampHash(obj); err != nil {
				return nil, err
			}
			want[obj.GetKind()][obj.GetName()] = obj
		}
	}
	return want, nil
}

// credential locates a server's credential: the grant the credential grants
// write for it (credentialgrants.GrantName) and its payload in OpenBao.
func (r *Reconciler) credential(server *v1alpha1.MCPServer) (*Credential, error) {
	c := server.Spec.Credential
	if c == nil {
		return nil, nil
	}
	if r.locator == nil {
		return nil, errors.New("spec.credential needs Secrets in OpenBao org namespaces")
	}
	namespace := server.Metadata.NamespaceOrDefault()
	path, err := r.locator.PayloadPath(namespace, c.SecretRef.Name)
	if err != nil {
		return nil, fmt.Errorf("spec.credential: %w", err)
	}
	cred := &Credential{
		Type:   c.CredentialType(),
		Org:    r.locator.OrgNamespace(namespace),
		Role:   credentialgrants.GrantName(namespace, server.Metadata.Name, c.SecretRef.Name),
		Path:   path,
		Header: c.HeaderName(),
	}
	switch cred.Type {
	case v1alpha1.MCPCredentialTypeStatic:
		cred.Key, cred.Scheme = c.SecretRef.Key, c.Scheme
	case v1alpha1.MCPCredentialTypeOAuthClientCredentials:
		o := c.OAuthClientCredentials
		if o == nil {
			return nil, errors.New("spec.credential.oauthClientCredentials is not set")
		}
		resource := o.Resource
		if resource == "" {
			if resource, err = CanonicalResource(server.Spec.Remote.URL); err != nil {
				return nil, fmt.Errorf("spec.credential: resource: %w", err)
			}
		}
		cred.Scheme = "Bearer"
		cred.OAuth = &OAuthClient{
			TokenURL: o.TokenURL, ClientIDKey: o.ClientIDKey, ClientSecretKey: o.ClientSecretKey,
			Scope: strings.Join(o.Scopes, " "), Resource: resource,
		}
	default:
		return nil, fmt.Errorf("spec.credential: unsupported type %q", c.Type)
	}
	return cred, nil
}

// stampHash records the digest of what Build generated.
func stampHash(obj *unstructured.Unstructured) error {
	data, err := json.Marshal([]any{obj.GetLabels(), obj.GetAnnotations(), obj.Object["spec"]})
	if err != nil {
		return fmt.Errorf("hash %s %s: %w", obj.GetKind(), obj.GetName(), err)
	}
	digest := sha256.Sum256(data)
	annotations := obj.GetAnnotations()
	annotations[specHashAnnotation] = fmt.Sprintf("%x", digest[:16])
	obj.SetAnnotations(annotations)
	return nil
}
