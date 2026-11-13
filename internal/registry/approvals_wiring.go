package registry

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/agentregistry-dev/agentregistry/internal/registry/approvals"
	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	pkgdb "github.com/agentregistry-dev/agentregistry/pkg/registry/database"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

// buildApprovals sets up approvals when APPROVALS_ENABLED: the service, the
// callback handler (when a callback URL is configured), and the loop that
// follows held requests. Every replica runs the loop; each step moves a
// request on with a compare-and-set, so only one replica applies it.
func buildApprovals(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, pdp *authzen.Client, recorder audit.Recorder) (*approvals.Service, http.Handler, error) {
	if !cfg.ApprovalsEnabled {
		return nil, nil, nil
	}
	if pdp == nil {
		return nil, nil, fmt.Errorf("approvals need the AuthZEN PDP (AUTH_MODE=required)")
	}
	secretValue, err := valueOrFile(cfg.ApprovalsClientSecret, cfg.ApprovalsClientSecretFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read approvals client secret: %w", err)
	}
	tokens, err := authzen.NewClientCredentialsTokenSource(authzen.ClientCredentialsConfig{
		TokenURL: cfg.ApprovalsTokenURL, ClientID: cfg.ApprovalsClientID, ClientSecret: secretValue, Scopes: cfg.ApprovalsScopes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("approvals credentials: %w", err)
	}
	ars, err := approvals.NewARSClient(pdp, cfg.AuthzenURL, tokens, &http.Client{Timeout: cfg.AuthzenTimeout * 4})
	if err != nil {
		return nil, nil, err
	}
	store := v1alpha1store.NewApprovalRequestStore(pool, pkgdb.OSSSchemaRegistry().MustGet(pkgdb.OSSSourceName))
	svc, err := approvals.New(approvals.Config{Store: store, ARS: ars, Audit: recorder, CallbackURL: cfg.ApprovalsCallbackURL})
	if err != nil {
		return nil, nil, err
	}
	var callback http.Handler
	if cfg.ApprovalsCallbackURL != "" {
		raw, err := os.ReadFile(cfg.ApprovalsCallbackSecretFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read APPROVALS_CALLBACK_SECRET_FILE: %w", err)
		}
		secret := []byte(strings.TrimSpace(string(raw)))
		if len(secret) < 32 {
			return nil, nil, fmt.Errorf("APPROVALS_CALLBACK_SECRET_FILE must hold at least 32 bytes")
		}
		callback = svc.CallbackHandler(secret)
	}
	go svc.Run(ctx, cfg.ApprovalsPollInterval)
	authLogger.Info("approvals enabled", "poll_interval", cfg.ApprovalsPollInterval.String(), "callback", cfg.ApprovalsCallbackURL != "")
	return svc, callback, nil
}
