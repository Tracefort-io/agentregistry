package registry

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1/registries"
	"github.com/agentregistry-dev/agentregistry/pkg/secret"
)

// buildRegistryValidator returns the package-registry validator for writes
// when OCI_REGISTRIES lists private OCI registries: their images are read with
// each registry's credentials, and every other package keeps the default
// checks. Nil, with no registries listed, keeps the default. resolver is nil
// without a secret store.
func buildRegistryValidator(cfg *config.Config, resolver secret.Resolver) (v1alpha1.RegistryValidatorFunc, error) {
	trusted, err := registries.LoadTrustedOCIRegistries(cfg.OCIRegistries, cfg.OCIRegistriesFile)
	if err != nil {
		return nil, fmt.Errorf("OCI_REGISTRIES: %w", err)
	}
	if len(trusted) == 0 {
		return nil, nil
	}
	for _, r := range trusted {
		if r.CredentialsSecret != "" && resolver == nil {
			return nil, fmt.Errorf("OCI_REGISTRIES: %s names credentials %s, but no secret store is configured", r.Host, r.CredentialsSecret)
		}
	}
	hosts := make([]string, len(trusted))
	for i, r := range trusted {
		hosts[i] = r.Host
	}
	authLogger.Info("private OCI registries trusted", "hosts", strings.Join(hosts, ","))
	return registries.NewDispatcher(trusted, ociCredentials(resolver)), nil
}

// ociCredentials reads a trusted registry's "username" and "password" from
// its registry Secret, on every check, so rotated credentials take effect at
// once.
func ociCredentials(resolver secret.Resolver) registries.OCICredentialsFunc {
	return func(ctx context.Context, r registries.TrustedOCIRegistry) (authn.Authenticator, error) {
		namespace, name, err := registries.SecretName(r.CredentialsSecret)
		if err != nil {
			return nil, err
		}
		values, err := resolver.ResolveAll(ctx, v1alpha1.SecretRef{Namespace: namespace, Name: name})
		if err != nil {
			return nil, err
		}
		username := strings.TrimSpace(string(values["username"].Reveal()))
		password := strings.TrimSpace(string(values["password"].Reveal()))
		if username == "" || password == "" {
			return nil, fmt.Errorf("secret %s/%s needs both %q and %q", namespace, name, "username", "password")
		}
		return &authn.Basic{Username: username, Password: password}, nil
	}
}
