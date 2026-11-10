package registry

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/agentregistry-dev/agentregistry/internal/registry/authz"
	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	jwtauthn "github.com/agentregistry-dev/agentregistry/pkg/registry/auth/jwt"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var authLogger = logging.New("auth-wiring")

// authWiring holds the authentication and authorization providers the server
// runs with. With AuthMode "required" they are built from config: a JWT
// AuthnProvider for the configured issuers and an AuthZEN PEP. Providers set
// in AppOptions always win.
type authWiring struct {
	authn auth.AuthnProvider
	authz auth.AuthzProvider
	// pdp is nil unless AuthMode is "required".
	pdp     *authzen.Client
	listMax int
}

// buildAuth resolves the providers before the database opens, which needs the
// AuthzProvider. Per-kind hooks need the stores and are added by applyHooks.
func buildAuth(ctx context.Context, cfg *config.Config, options types.AppOptions) (authWiring, error) {
	w := authWiring{authn: options.AuthnProvider, authz: options.AuthzProvider}
	if cfg.AuthMode != config.AuthModeRequired {
		return w, nil
	}

	if w.authn == nil {
		issuers, err := jwtauthn.LoadIssuers(cfg.AuthIssuers, cfg.AuthIssuersFile)
		if err != nil {
			return authWiring{}, fmt.Errorf("load auth issuers: %w", err)
		}
		provider, err := jwtauthn.NewProvider(ctx, issuers, cfg.AuthClockSkew)
		if err != nil {
			return authWiring{}, fmt.Errorf("create jwt authn provider: %w", err)
		}
		w.authn = provider
		authLogger.Info("jwt authentication enabled", "issuers", issuerNames(issuers))
	}

	tokens, err := pdpTokenSource(cfg)
	if err != nil {
		return authWiring{}, err
	}
	w.pdp, err = authzen.New(authzen.Config{
		BaseURL:     cfg.AuthzenURL,
		Timeout:     cfg.AuthzenTimeout,
		CacheTTL:    cfg.AuthzenCacheTTL,
		TokenSource: tokens,
	})
	if err != nil {
		return authWiring{}, fmt.Errorf("create authzen client: %w", err)
	}
	w.listMax = cfg.AuthzenListMax

	if w.authz == nil {
		// The database layer gets a PEP without a candidate lister: the
		// stores do not exist yet, and it only makes single-resource checks.
		pep, err := authz.New(authz.Config{Client: w.pdp, ListMax: w.listMax})
		if err != nil {
			return authWiring{}, fmt.Errorf("create authz pep: %w", err)
		}
		w.authz = pep
	}
	authLogger.Info("authzen authorization enabled", "pdp", cfg.AuthzenURL)
	return w, nil
}

// applyHooks installs the PEP's per-kind Authorizers and ListFilters into
// options for every kind with a store, so the resource handlers, the batch
// apply endpoint and the MCP bridge all ask the PDP. Hooks already set in
// options win per kind.
func (w authWiring) applyHooks(options *types.AppOptions, stores map[string]*v1alpha1store.Store) error {
	if w.pdp == nil {
		return nil
	}
	var extra []string
	for kind := range stores {
		if !slices.Contains(authz.BuiltinKinds, kind) {
			extra = append(extra, kind)
		}
	}
	slices.Sort(extra)
	pep, err := authz.New(authz.Config{
		Client:     w.pdp,
		Lister:     authz.NewStoreLister(stores),
		ListMax:    w.listMax,
		ExtraKinds: extra,
	})
	if err != nil {
		return fmt.Errorf("create authz pep: %w", err)
	}
	options.Authorizers = mergeHooks(pep.Authorizers(), options.Authorizers)
	options.ListFilters = mergeHooks(pep.ListFilters(), options.ListFilters)
	return nil
}

// mergeHooks returns base with every entry of override applied on top.
func mergeHooks[V any](base, override map[string]V) map[string]V {
	out := maps.Clone(base)
	maps.Copy(out, override)
	return out
}

// pdpTokenSource is how the registry authenticates to the PDP: OAuth 2.0
// client credentials, a static bearer token, or nothing.
func pdpTokenSource(cfg *config.Config) (authzen.TokenSource, error) {
	if cfg.AuthzenTokenURL != "" {
		secretValue, err := valueOrFile(cfg.AuthzenClientSecret, cfg.AuthzenClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("read authzen client secret: %w", err)
		}
		tokens, err := authzen.NewClientCredentialsTokenSource(authzen.ClientCredentialsConfig{
			TokenURL:     cfg.AuthzenTokenURL,
			ClientID:     cfg.AuthzenClientID,
			ClientSecret: secretValue,
			Scopes:       cfg.AuthzenScopes,
		})
		if err != nil {
			return nil, fmt.Errorf("create authzen token source: %w", err)
		}
		return tokens, nil
	}
	static, err := valueOrFile(cfg.AuthzenStaticToken, cfg.AuthzenStaticTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read authzen static token: %w", err)
	}
	if static == "" {
		authLogger.Warn("no credentials configured for the authzen pdp; requests are sent without a token")
		return nil, nil
	}
	return authzen.StaticToken(static), nil
}

// valueOrFile returns the trimmed contents of file when it is set, else value.
func valueOrFile(value, file string) (string, error) {
	if file == "" {
		return value, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func issuerNames(issuers []jwtauthn.IssuerConfig) []string {
	out := make([]string, 0, len(issuers))
	for _, i := range issuers {
		out = append(out, i.Issuer)
	}
	return out
}
