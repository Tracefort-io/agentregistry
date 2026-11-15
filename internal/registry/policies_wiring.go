package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/githost"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/opaeval"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/gitutil"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// policyRepoLimits caps one read of the policy repository.
var policyRepoLimits = gitutil.Limits{MaxBytes: 32 << 20, MaxEntries: 5000}

// buildPolicies sets up policies when POLICIES_ENABLED: the service behind
// /v0/policies and the webhook handler that tags merged changes.
func buildPolicies(cfg *config.Config, credentials types.GitCredentialFunc, authorizer policies.Authorizer, recorder audit.Recorder) (*policies.Service, http.Handler, error) {
	if !cfg.PoliciesEnabled {
		return nil, nil, nil
	}
	if credentials == nil {
		return nil, nil, fmt.Errorf("policies need a secret store for POLICIES_CREDENTIALS_SECRET")
	}
	raw, err := os.ReadFile(cfg.PoliciesWebhookSecretFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read POLICIES_WEBHOOK_SECRET_FILE: %w", err)
	}
	webhookSecret := []byte(strings.TrimSpace(string(raw)))
	if len(webhookSecret) < 32 {
		return nil, nil, fmt.Errorf("POLICIES_WEBHOOK_SECRET_FILE must hold at least 32 bytes")
	}
	namespace, name, found := strings.Cut(cfg.PoliciesCredentialsSecret, "/")
	if !found {
		namespace, name = v1alpha1.DefaultNamespace, cfg.PoliciesCredentialsSecret
	}
	repoRef := &v1alpha1.Repository{URL: cfg.PoliciesRepoURL, CredentialsRef: &v1alpha1.LocalSecretReference{Name: name}}
	httpClient := &http.Client{Timeout: 30 * time.Second}

	// Credentials are resolved on every call, so a rotated token takes effect at once.
	open := func(ctx context.Context) (policies.GitRepo, githost.Host, error) {
		userinfo, err := credentials(ctx, namespace, repoRef)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve policy repository credentials: %w", err)
		}
		userinfo = gitUserinfo(cfg.PoliciesProvider, userinfo)
		repo, err := gitutil.OpenRepo(cfg.PoliciesRepoURL, userinfo, policyRepoLimits)
		if err != nil {
			return nil, nil, err
		}
		host, err := githost.New(githost.Config{
			Provider: cfg.PoliciesProvider, RepoURL: cfg.PoliciesRepoURL, APIURL: cfg.PoliciesAPIURL,
			Token: policies.TokenFrom(userinfo), WebhookSecret: webhookSecret, HTTPClient: httpClient,
		})
		if err != nil {
			return nil, nil, err
		}
		return repo, host, nil
	}
	// Fail at startup on a misconfigured repository URL or provider rather than on first use.
	if _, err := gitutil.OpenRepo(cfg.PoliciesRepoURL, nil, policyRepoLimits); err != nil {
		return nil, nil, fmt.Errorf("POLICIES_REPO_URL: %w", err)
	}
	if _, err := githost.New(githost.Config{Provider: cfg.PoliciesProvider, RepoURL: cfg.PoliciesRepoURL, APIURL: cfg.PoliciesAPIURL}); err != nil {
		return nil, nil, err
	}

	var opa policies.LoadedModules
	if cfg.PoliciesOPAURL != "" {
		token, err := valueOrFile("", cfg.PoliciesOPATokenFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read POLICIES_OPA_TOKEN_FILE: %w", err)
		}
		opa = &policies.OPAClient{URL: cfg.PoliciesOPAURL, Token: token, HTTP: httpClient}
	}
	svc, err := policies.New(policies.Config{
		Open: open, Branch: cfg.PoliciesBranch, Authorizer: authorizer, OPA: opa, Audit: recorder,
		Engine:    opaeval.New(cfg.PoliciesEvalTimeout),
		Committer: gitutil.Signature{Name: cfg.PoliciesCommitterName, Email: cfg.PoliciesCommitterEmail},
	})
	if err != nil {
		return nil, nil, err
	}
	authLogger.Info("policies enabled", "provider", cfg.PoliciesProvider, "repository", cfg.PoliciesRepoURL,
		"branch", cfg.PoliciesBranch, "opa", cfg.PoliciesOPAURL != "")
	return svc, svc.WebhookHandler(), nil
}

// gitUserinfo turns a token-only credential into the username/password pair
// each host expects for git over HTTPS.
func gitUserinfo(provider string, u *url.Userinfo) *url.Userinfo {
	if u == nil {
		return nil
	}
	if _, hasPassword := u.Password(); hasPassword {
		return u
	}
	user := "x-access-token"
	if provider == githost.ProviderGitLab {
		user = "oauth2"
	}
	return url.UserPassword(user, u.Username())
}
