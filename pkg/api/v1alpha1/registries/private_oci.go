package registries

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
)

// TrustedOCIRegistry is a private OCI registry whose images may be
// registered. Its images skip the public allowlist but get the same checks
// as public ones: an explicit tag or digest, the image exists, and its
// io.modelcontextprotocol.server.name label matches the server name.
type TrustedOCIRegistry struct {
	// Host is the registry as it appears in image references, with the
	// port when there is one (e.g. "harbor.example.com:8443").
	Host string `json:"host"`
	// CredentialsSecret names the registry Secret with the "username" and
	// "password" to read images with, "<name>" or "<namespace>/<name>".
	// Empty reads anonymously.
	CredentialsSecret string `json:"credentialsSecret,omitempty"`
	// Insecure reads the registry over plain HTTP.
	Insecure bool `json:"insecure,omitempty"`
}

// hostPattern is a registry host with an optional port: DNS labels, an IPv4
// address, or a bracketed IPv6 address.
var hostPattern = regexp.MustCompile(`^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:[0-9]{1,5})?$`)

// LoadTrustedOCIRegistries reads a JSON array of TrustedOCIRegistry from
// inline, or from file when file is set. Both empty is no registries.
func LoadTrustedOCIRegistries(inline, file string) ([]TrustedOCIRegistry, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("reading OCI registries file: %w", err)
		}
		inline = string(b)
	}
	if strings.TrimSpace(inline) == "" {
		return nil, nil
	}
	var registries []TrustedOCIRegistry
	dec := json.NewDecoder(strings.NewReader(inline))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&registries); err != nil {
		return nil, fmt.Errorf("parsing OCI registries: %w", err)
	}
	seen := make(map[string]bool, len(registries))
	for i := range registries {
		r := &registries[i]
		r.Host = strings.ToLower(strings.TrimSpace(r.Host))
		if !hostPattern.MatchString(r.Host) {
			return nil, fmt.Errorf("OCI registry %d: host %q must be a registry host with an optional port, without a scheme or path", i, r.Host)
		}
		if seen[r.Host] {
			return nil, fmt.Errorf("OCI registry %q is listed twice", r.Host)
		}
		seen[r.Host] = true
		if r.CredentialsSecret != "" {
			if _, _, err := SecretName(r.CredentialsSecret); err != nil {
				return nil, fmt.Errorf("OCI registry %q: %w", r.Host, err)
			}
		}
	}
	return registries, nil
}

// SecretName splits a "<name>" or "<namespace>/<name>" Secret reference; a
// bare name is in the default namespace.
func SecretName(ref string) (namespace, secretName string, err error) {
	namespace, secretName, found := strings.Cut(ref, "/")
	if !found {
		namespace, secretName = v1alpha1.DefaultNamespace, ref
	}
	if namespace == "" || secretName == "" || strings.Contains(secretName, "/") {
		return "", "", fmt.Errorf("credentialsSecret %q must be <name> or <namespace>/<name>", ref)
	}
	return namespace, secretName, nil
}

// OCICredentialsFunc returns the credentials to read a trusted registry
// with. It is called on every check, so rotated credentials take effect at
// once.
type OCICredentialsFunc func(ctx context.Context, r TrustedOCIRegistry) (authn.Authenticator, error)

// NewDispatcher returns a RegistryValidatorFunc like Dispatcher, except that
// an OCI image on a trusted registry is read with that registry's
// credentials instead of being held to the public allowlist. Every other
// package is validated exactly as Dispatcher does.
func NewDispatcher(trusted []TrustedOCIRegistry, credentials OCICredentialsFunc) v1alpha1.RegistryValidatorFunc {
	byHost := make(map[string]TrustedOCIRegistry, len(trusted))
	for _, r := range trusted {
		byHost[strings.ToLower(r.Host)] = r
	}
	return func(ctx context.Context, origin v1alpha1.MCPPackageOrigin, serverName string) error {
		if origin.OCI != nil {
			if r, ok := byHost[strings.ToLower(referenceRegistry(origin.Identifier))]; ok {
				return validateTrustedOCI(ctx, r, credentials, origin, serverName)
			}
		}
		return Dispatcher(ctx, origin, serverName)
	}
}

// referenceRegistry is the registry an image reference names, as the
// reference parser reads it; "" when it doesn't parse.
func referenceRegistry(identifier string) string {
	ref, err := name.ParseReference(identifier)
	if err != nil {
		return ""
	}
	return ref.Context().RegistryStr()
}

// trustedReference parses identifier for r, over plain HTTP when r is
// Insecure.
func trustedReference(r TrustedOCIRegistry, identifier string) (name.Reference, error) {
	var opts []name.Option
	if r.Insecure {
		opts = append(opts, name.Insecure)
	}
	return name.ParseReference(identifier, opts...)
}

func validateTrustedOCI(ctx context.Context, r TrustedOCIRegistry, credentials OCICredentialsFunc, origin v1alpha1.MCPPackageOrigin, serverName string) error {
	if err := checkOCIIdentifier(origin); err != nil {
		return err
	}
	ref, err := trustedReference(r, origin.Identifier)
	if err != nil {
		return fmt.Errorf("invalid OCI reference: %w", err)
	}
	auth := authn.Anonymous
	if r.CredentialsSecret != "" {
		if credentials == nil {
			return fmt.Errorf("OCI registry %s: no way to read its credentials %s", r.Host, r.CredentialsSecret)
		}
		if auth, err = credentials(ctx, r); err != nil {
			return fmt.Errorf("OCI registry %s: credentials %s: %w", r.Host, r.CredentialsSecret, err)
		}
		if auth == nil {
			return fmt.Errorf("OCI registry %s: credentials %s resolved to nothing", r.Host, r.CredentialsSecret)
		}
	}
	unauthorized := fmt.Sprintf("OCI registry %s refused to read '%s': check that its credentials (%s) may pull it", r.Host, origin.Identifier, credentialsLabel(r))
	return checkOCIImage(ctx, ref, origin.Identifier, serverName, auth, unauthorized)
}

func credentialsLabel(r TrustedOCIRegistry) string {
	if r.CredentialsSecret == "" {
		return "anonymous"
	}
	return "Secret " + r.CredentialsSecret
}
