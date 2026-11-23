// Package credentialgrants keeps OpenBao's grants of MCP server credentials
// in step with the registry: for each MCP server with a credential, a policy
// that reads only that credential and a role of the org's JWT auth method
// that gives it to the workload identities of the Deployments whose Agent
// lists the server. agentgateway logs in with the calling agent's JWT-SVID to
// fetch the credential after authorizing the call; OpenBao decides
// independently whether that identity may have it.
//
// Grants never cross orgs: a server's credential is granted only to
// Deployments in the server's own namespace.
package credentialgrants

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/secret/openbao"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var logger = logging.New("credential-grants")

// Writer manages the grant objects in OpenBao (openbao.Grants).
type Writer interface {
	PutPolicy(ctx context.Context, org, name, hcl string) error
	DeletePolicy(ctx context.Context, org, name string) error
	PutRole(ctx context.Context, org, name string, role openbao.GrantRole) error
	DeleteRole(ctx context.Context, org, name string) error
	ListRoles(ctx context.Context, org string) ([]string, error)
	ListPolicies(ctx context.Context, org string) ([]string, error)
	ListOrgs(ctx context.Context, prefix string) ([]string, error)
}

// Locator says where a registry namespace's Secrets live (openbao.Store with
// org namespaces).
type Locator interface {
	OrgNamespace(namespace string) string
	PayloadPath(namespace, name string) (string, error)
}

// DeploymentLister lists every Deployment, terminating ones included.
type DeploymentLister func(ctx context.Context) ([]*types.DeploymentRecord, error)

// RevokedFilter reports which identity prefixes were revoked (the identity
// history); a revoked identity never gets a grant again.
type RevokedFilter func(ctx context.Context, prefixes []string) (map[string]bool, error)

// Config sets the grants' constants.
type Config struct {
	// OrgPrefix names org namespaces (the secret store's org namespace prefix).
	OrgPrefix string
	// Audience the JWT-SVIDs must carry (default "openbao").
	Audience string
	// TTLSeconds of a login token (default 60); it may be used once, for the
	// one read of the credential.
	TTLSeconds int
}

// Reconciler computes and applies the grants. Syncs run one at a time.
type Reconciler struct {
	writer      Writer
	locator     Locator
	deployments DeploymentLister
	revoked     RevokedFilter
	getter      v1alpha1.GetterFunc
	config      Config

	mu sync.Mutex
}

// New returns a Reconciler.
func New(writer Writer, locator Locator, deployments DeploymentLister, revoked RevokedFilter, getter v1alpha1.GetterFunc, config Config) (*Reconciler, error) {
	if writer == nil || locator == nil || deployments == nil || revoked == nil || getter == nil {
		return nil, errors.New("credential grants: writer, locator, deployment lister, revoked filter and getter are required")
	}
	if config.OrgPrefix == "" {
		return nil, errors.New("credential grants: an org namespace prefix is required")
	}
	if config.Audience == "" {
		config.Audience = "openbao"
	}
	if config.TTLSeconds <= 0 {
		config.TTLSeconds = 60
	}
	return &Reconciler{writer: writer, locator: locator, deployments: deployments, revoked: revoked, getter: getter, config: config}, nil
}

var invalidNameChars = regexp.MustCompile(`[^a-z0-9]+`)

// GrantName names the policy and role granting one MCP server's credential:
// readable, and unique for (namespace, server, Secret) whatever the names
// hold. agentgateway logs in with the role of this name.
func GrantName(namespace, server, secret string) string {
	readable := strings.Trim(invalidNameChars.ReplaceAllString(strings.ToLower(server), "-"), "-")
	if len(readable) > 30 {
		readable = strings.TrimRight(readable[:30], "-")
	}
	digest := sha256.Sum256([]byte(namespace + "/" + server + "/" + secret))
	if readable == "" {
		return fmt.Sprintf("%s%x", openbao.NamePrefix, digest[:6])
	}
	return fmt.Sprintf("%s%s-%x", openbao.NamePrefix, readable, digest[:6])
}

// grant is one credential and the identity prefixes allowed to read it.
type grant struct {
	path     string
	prefixes []string
}

// desired computes the grants, by org namespace and grant name. Identities in
// exclude get none (one being revoked).
func (r *Reconciler) desired(ctx context.Context, exclude []string) (map[string]map[string]*grant, error) {
	deployments, err := r.deployments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	var prefixes []string
	for _, d := range deployments {
		if p := d.InternalMeta.ActorSubject; p != "" {
			prefixes = append(prefixes, p)
		}
	}
	revoked, err := r.revoked(ctx, prefixes)
	if err != nil {
		return nil, fmt.Errorf("read revoked identities: %w", err)
	}
	out := map[string]map[string]*grant{}
	for _, d := range deployments {
		prefix := d.InternalMeta.ActorSubject
		// A Deployment being deleted loses its grants at once; a revoked
		// identity never has one again.
		if prefix == "" || slices.Contains(exclude, prefix) || revoked[prefix] ||
			d.Metadata.DeletionTimestamp != nil || v1alpha1.IsDiscoveredDeployment(d.Deployment) {
			continue
		}
		namespace := d.Metadata.NamespaceOrDefault()
		agentRef := d.Spec.TargetRef
		if agentRef.Kind != v1alpha1.KindAgent {
			continue
		}
		agentRef.Namespace = orDefault(agentRef.Namespace, namespace)
		object, err := r.getter(ctx, agentRef)
		if err != nil {
			logger.Warn("credential grants: agent not found", "deployment", namespace+"/"+d.Metadata.Name, "error", err)
			continue
		}
		agent, ok := object.(*v1alpha1.Agent)
		if !ok {
			continue
		}
		for _, serverRef := range agent.Spec.MCPServers {
			serverRef.Kind = orDefault(serverRef.Kind, v1alpha1.KindMCPServer)
			serverRef.Namespace = orDefault(serverRef.Namespace, agent.Metadata.NamespaceOrDefault())
			if serverRef.Namespace != namespace {
				logger.Warn("credential grants: no grant across orgs",
					"deployment", namespace+"/"+d.Metadata.Name, "mcp_server", serverRef.Namespace+"/"+serverRef.Name)
				continue
			}
			object, err := r.getter(ctx, serverRef)
			if err != nil {
				logger.Warn("credential grants: MCP server not found", "mcp_server", serverRef.Namespace+"/"+serverRef.Name, "error", err)
				continue
			}
			server, ok := object.(*v1alpha1.MCPServer)
			if !ok || server.Spec.Credential == nil {
				continue
			}
			secret := server.Spec.Credential.SecretRef.Name
			path, err := r.locator.PayloadPath(namespace, secret)
			if err != nil {
				logger.Warn("credential grants: invalid credential", "mcp_server", namespace+"/"+server.Metadata.Name, "error", err)
				continue
			}
			org := r.locator.OrgNamespace(namespace)
			name := GrantName(namespace, server.Metadata.Name, secret)
			if out[org] == nil {
				out[org] = map[string]*grant{}
			}
			g := out[org][name]
			if g == nil {
				g = &grant{path: path}
				out[org][name] = g
			}
			if glob := prefix + "*"; !slices.Contains(g.prefixes, glob) {
				g.prefixes = append(g.prefixes, glob)
			}
		}
	}
	return out, nil
}

// Sync makes OpenBao's grants match the registry: writes every desired
// policy and role, and removes managed ones no longer desired (the role
// before its policy). Identities in exclude lose their grants. It goes on
// past a failure and returns all of them.
func (r *Reconciler) Sync(ctx context.Context, exclude ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	want, err := r.desired(ctx, exclude)
	if err != nil {
		return err
	}
	orgs, err := r.writer.ListOrgs(ctx, r.config.OrgPrefix)
	if err != nil {
		return err
	}
	for org := range want {
		if !slices.Contains(orgs, org) {
			orgs = append(orgs, org)
		}
	}
	slices.Sort(orgs)

	var errs []error
	for _, org := range orgs {
		grants := want[org]
		names := make([]string, 0, len(grants))
		for name := range grants {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			g := grants[name]
			slices.Sort(g.prefixes)
			policy := fmt.Sprintf("path %q {\n  capabilities = [\"read\"]\n}\n", g.path)
			if err := r.writer.PutPolicy(ctx, org, name, policy); err != nil {
				errs = append(errs, err)
				continue
			}
			role := openbao.GrantRole{
				Audience: r.config.Audience, SubjectGlobs: g.prefixes, Policy: name,
				TTLSeconds: r.config.TTLSeconds, NumUses: 1,
			}
			if err := r.writer.PutRole(ctx, org, name, role); err != nil {
				errs = append(errs, err)
			}
		}
		roles, err := r.writer.ListRoles(ctx, org)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, name := range roles {
			if _, ok := grants[name]; !ok {
				if err := r.writer.DeleteRole(ctx, org, name); err != nil {
					errs = append(errs, err)
				}
			}
		}
		policies, err := r.writer.ListPolicies(ctx, org)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, name := range policies {
			if _, ok := grants[name]; !ok {
				if err := r.writer.DeletePolicy(ctx, org, name); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// Revoke removes the grants of the identity prefix, before its revocation is
// recorded.
func (r *Reconciler) Revoke(ctx context.Context, prefix string) error {
	if err := r.Sync(ctx, prefix); err != nil {
		return fmt.Errorf("remove credential grants of %s: %w", prefix, err)
	}
	slog.Debug("credential grants removed", "identity", prefix)
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
