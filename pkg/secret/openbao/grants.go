package openbao

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Grants writes, in org namespaces, the OpenBao objects that let a workload
// identity read one credential: an ACL policy and a role of the org's JWT
// auth method (verifying SPIFFE JWT-SVIDs) bound to the identities allowed.
// Every name it writes, lists or deletes starts with NamePrefix, so it never
// touches anything else in the namespace.
type Grants struct {
	client *Client
	// mount is the JWT auth method's path in each org namespace.
	mount string
}

// NamePrefix starts every policy and role Grants manages.
const NamePrefix = "mcp-"

// GrantRole is a role of the org's JWT auth method.
type GrantRole struct {
	// Audience the JWT-SVID must carry.
	Audience string
	// SubjectGlobs: the JWT-SVID's sub must match one ("<prefix>*").
	SubjectGlobs []string
	// Policy is the ACL policy the login token gets.
	Policy string
	// TTLSeconds of the login token, which may be used NumUses times.
	TTLSeconds int
	NumUses    int
}

// NewGrants returns a Grants on the JWT auth method at mount.
func NewGrants(client *Client, mount string) (*Grants, error) {
	if client == nil {
		return nil, errors.New("openbao: a client is required")
	}
	m, err := cleanPath(mount)
	if err != nil || m == "" {
		return nil, fmt.Errorf("openbao: invalid auth mount %q", mount)
	}
	return &Grants{client: client, mount: m}, nil
}

func checkGrantName(name string) error {
	if !strings.HasPrefix(name, NamePrefix) || checkSegment(name) != nil {
		return fmt.Errorf("openbao: grant name %q must start with %q and be one path segment", name, NamePrefix)
	}
	return nil
}

// PutPolicy writes policy name in org.
func (g *Grants) PutPolicy(ctx context.Context, org, name, hcl string) error {
	if err := checkGrantName(name); err != nil {
		return err
	}
	if err := g.client.DoIn(ctx, org, http.MethodPut, "sys/policies/acl/"+name, map[string]any{"policy": hcl}, nil); err != nil {
		return fmt.Errorf("write policy %s/%s: %w", org, name, err)
	}
	return nil
}

// DeletePolicy removes policy name from org; a missing one is fine.
func (g *Grants) DeletePolicy(ctx context.Context, org, name string) error {
	if err := checkGrantName(name); err != nil {
		return err
	}
	if err := g.client.DoIn(ctx, org, http.MethodDelete, "sys/policies/acl/"+name, nil, nil); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("delete policy %s/%s: %w", org, name, err)
	}
	return nil
}

// PutRole writes role name in org.
func (g *Grants) PutRole(ctx context.Context, org, name string, role GrantRole) error {
	if err := checkGrantName(name); err != nil {
		return err
	}
	if role.Audience == "" || len(role.SubjectGlobs) == 0 || role.Policy == "" || role.TTLSeconds <= 0 || role.NumUses <= 0 {
		return fmt.Errorf("openbao: role %s needs an audience, subjects, a policy, a TTL and a use count", name)
	}
	body := map[string]any{
		"role_type":         "jwt",
		"user_claim":        "sub",
		"bound_audiences":   []string{role.Audience},
		"bound_claims_type": "glob",
		"bound_claims":      map[string]any{"sub": role.SubjectGlobs},
		"token_policies":    []string{role.Policy},
		// The token reads the credential and nothing else: not even
		// OpenBao's default policy (self lookup, cubbyhole, ...).
		"token_no_default_policy": true,
		"token_ttl":               role.TTLSeconds,
		"token_max_ttl":           role.TTLSeconds,
		"token_num_uses":          role.NumUses,
		"token_type":              "service",
	}
	if err := g.client.DoIn(ctx, org, http.MethodPost, "auth/"+g.mount+"/role/"+name, body, nil); err != nil {
		return fmt.Errorf("write role %s/%s: %w", org, name, err)
	}
	return nil
}

// DeleteRole removes role name from org; a missing one is fine.
func (g *Grants) DeleteRole(ctx context.Context, org, name string) error {
	if err := checkGrantName(name); err != nil {
		return err
	}
	if err := g.client.DoIn(ctx, org, http.MethodDelete, "auth/"+g.mount+"/role/"+name, nil, nil); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("delete role %s/%s: %w", org, name, err)
	}
	return nil
}

// ListRoles returns the names of org's roles that Grants manages.
func (g *Grants) ListRoles(ctx context.Context, org string) ([]string, error) {
	return g.list(ctx, org, "auth/"+g.mount+"/role")
}

// ListPolicies returns the names of org's policies that Grants manages.
func (g *Grants) ListPolicies(ctx context.Context, org string) ([]string, error) {
	return g.list(ctx, org, "sys/policies/acl")
}

// ListOrgs returns the child namespaces of the client's namespace that start
// with prefix.
func (g *Grants) ListOrgs(ctx context.Context, prefix string) ([]string, error) {
	keys, err := g.listKeys(ctx, "", "sys/namespaces")
	if err != nil {
		return nil, fmt.Errorf("list org namespaces: %w", err)
	}
	var orgs []string
	for _, key := range keys {
		if name := strings.TrimSuffix(key, "/"); strings.HasPrefix(name, prefix) {
			orgs = append(orgs, name)
		}
	}
	return orgs, nil
}

func (g *Grants) list(ctx context.Context, org, path string) ([]string, error) {
	keys, err := g.listKeys(ctx, org, path)
	if err != nil {
		return nil, fmt.Errorf("list %s/%s: %w", org, path, err)
	}
	var names []string
	for _, key := range keys {
		if strings.HasPrefix(key, NamePrefix) {
			names = append(names, key)
		}
	}
	return names, nil
}

func (g *Grants) listKeys(ctx context.Context, org, path string) ([]string, error) {
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := g.client.DoIn(ctx, org, "LIST", path, nil, &resp); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return resp.Data.Keys, nil
}
