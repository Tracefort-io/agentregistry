package openbao

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/secret"
)

// healthPath is read by Check; it never exists.
const healthPath = ".agentregistry-healthcheck"

// Store keeps each Secret's payload in a KV version 2 engine, at
// <mount>/data/<prefix>/<namespace>/<name>. Values are stored base64-encoded,
// as Kubernetes Secrets store them, so any bytes round-trip.
//
// With org namespaces (WithOrgNamespaces), the Secrets of each registry
// namespace live in their own OpenBao namespace, <orgPrefix><namespace>, at
// <mount>/data/<prefix>/<name>: each org's credentials are confined to its
// namespace, and so is anything that administers them there.
type Store struct {
	client    *Client
	mount     string
	prefix    string
	orgPrefix string
}

var _ secret.Store = (*Store)(nil)

// Option configures a Store.
type Option func(*Store) error

// WithOrgNamespaces keeps each registry namespace's Secrets in the OpenBao
// namespace orgPrefix + namespace, a child of the client's namespace.
func WithOrgNamespaces(orgPrefix string) Option {
	return func(s *Store) error {
		if orgPrefix == "" || checkSegment(orgPrefix+"x") != nil || url.PathEscape(orgPrefix) != orgPrefix {
			return fmt.Errorf("openbao: invalid org namespace prefix %q", orgPrefix)
		}
		s.orgPrefix = orgPrefix
		return nil
	}
}

// New returns a Store on the KV v2 engine at mount, under prefix.
func New(client *Client, mount, prefix string, options ...Option) (*Store, error) {
	if client == nil {
		return nil, errors.New("openbao: a client is required")
	}
	m, err := cleanPath(mount)
	if err != nil || m == "" {
		return nil, fmt.Errorf("openbao: invalid mount %q", mount)
	}
	p, err := cleanPath(prefix)
	if err != nil {
		return nil, fmt.Errorf("openbao: invalid path prefix %q", prefix)
	}
	s := &Store{client: client, mount: m, prefix: p}
	for _, option := range options {
		if err := option(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Grants returns the grant writer for the JWT auth method at mount in the
// org namespaces, using the store's client.
func (s *Store) Grants(mount string) (*Grants, error) {
	return NewGrants(s.client, mount)
}

// OrgNamespacePrefix is the prefix of the org namespaces; empty without them.
func (s *Store) OrgNamespacePrefix() string { return s.orgPrefix }

// OrgNamespace is the OpenBao namespace (a child of the client's) holding
// namespace's Secrets; empty without org namespaces.
func (s *Store) OrgNamespace(namespace string) string {
	if s.orgPrefix == "" {
		return ""
	}
	if namespace == "" {
		namespace = v1alpha1.DefaultNamespace
	}
	return s.orgPrefix + namespace
}

// PayloadPath is the KV v2 data path of a Secret's payload, inside
// OrgNamespace(namespace): what an OpenBao policy must name to read it.
func (s *Store) PayloadPath(namespace, name string) (string, error) {
	_, path, err := s.locate("data", namespace, name)
	return path, err
}

// Type implements the store type the registry reports.
func (*Store) Type() secret.StoreType { return secret.StoreTypeOpenBao }

// Put replaces the Secret's payload with data (a new KV version).
func (s *Store) Put(ctx context.Context, namespace, name string, data map[string][]byte) error {
	org, path, err := s.locate("data", namespace, name)
	if err != nil {
		return err
	}
	encoded := make(map[string]string, len(data))
	for k, v := range data {
		encoded[k] = base64.StdEncoding.EncodeToString(v)
	}
	if err := s.client.DoIn(ctx, org, http.MethodPost, path, map[string]any{"data": encoded}, nil); err != nil {
		return fmt.Errorf("write secret payload %s: %w", ref(namespace, name), err)
	}
	return nil
}

// Get returns the latest version of the Secret's payload.
func (s *Store) Get(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	org, path, err := s.locate("data", namespace, name)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data *struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := s.client.DoIn(ctx, org, http.MethodGet, path, nil, &resp); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, secret.ErrPayloadNotFound
		}
		return nil, fmt.Errorf("read secret payload %s: %w", ref(namespace, name), err)
	}
	// A soft-deleted latest version has no data.
	if resp.Data == nil || resp.Data.Data == nil {
		return nil, secret.ErrPayloadNotFound
	}
	out := make(map[string][]byte, len(resp.Data.Data))
	for k, v := range resp.Data.Data {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("read secret payload %s: key %q is not a string", ref(namespace, name), k)
		}
		raw, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("read secret payload %s: key %q is not base64", ref(namespace, name), k)
		}
		out[k] = raw
	}
	return out, nil
}

// Delete removes the Secret's payload and every earlier version of it.
func (s *Store) Delete(ctx context.Context, namespace, name string) error {
	org, path, err := s.locate("metadata", namespace, name)
	if err != nil {
		return err
	}
	if err := s.client.DoIn(ctx, org, http.MethodDelete, path, nil, nil); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("delete secret payload %s: %w", ref(namespace, name), err)
	}
	return nil
}

// Check logs in and reads a path that does not exist, which proves the
// address, credentials, mount and policy work. With org namespaces it checks
// the default namespace's org.
func (s *Store) Check(ctx context.Context) error {
	path := s.mount + "/data/" + join(s.prefix, healthPath)
	org := s.OrgNamespace(v1alpha1.DefaultNamespace)
	if err := s.client.DoIn(ctx, org, http.MethodGet, path, nil, nil); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// locate returns the OpenBao namespace (a child of the client's; empty for
// its own) and the path of a Secret: <mount>/<kind>/<prefix>/<namespace>/<name>,
// or, with org namespaces, <mount>/<kind>/<prefix>/<name> in the org's
// namespace. Each segment is checked and escaped so a name cannot reach
// outside the prefix.
func (s *Store) locate(kind, namespace, name string) (string, string, error) {
	if namespace == "" {
		namespace = v1alpha1.DefaultNamespace
	}
	for _, seg := range []string{namespace, name} {
		if err := checkSegment(seg); err != nil {
			return "", "", fmt.Errorf("secret payload %s: %w", ref(namespace, name), err)
		}
	}
	if s.orgPrefix != "" {
		return s.OrgNamespace(namespace), s.mount + "/" + kind + "/" + join(s.prefix, url.PathEscape(name)), nil
	}
	return "", s.mount + "/" + kind + "/" + join(s.prefix, url.PathEscape(namespace), url.PathEscape(name)), nil
}

func checkSegment(seg string) error {
	if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "/\\") {
		return fmt.Errorf("invalid name segment %q", seg)
	}
	return nil
}

// cleanPath validates a slash-separated path and escapes each segment.
func cleanPath(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if err := checkSegment(seg); err != nil {
			return "", err
		}
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/"), nil
}

func join(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}

func ref(namespace, name string) string { return namespace + "/" + name }
