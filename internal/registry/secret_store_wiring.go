package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/secret"
	"github.com/agentregistry-dev/agentregistry/pkg/secret/openbao"
)

const (
	openBaoCheckTimeout = 15 * time.Second
	migrationPageSize   = 200
	// A migration pass with failures is run again after migrationRetryFirst,
	// doubling up to migrationRetryMax: the stores may be unreachable for a
	// while after the registry starts.
	migrationRetryFirst = 5 * time.Second
	migrationRetryMax   = 5 * time.Minute
)

// buildOpenBaoStore returns the OpenBao payload store and checks, without
// failing startup, that it can log in and reach its mount: OpenBao may come
// up after the registry, and Secret reads and writes report the cause. With
// orgNamespacePrefix it keeps each registry namespace's Secrets in its own
// OpenBao namespace; empty gives the single-namespace layout.
func buildOpenBaoStore(ctx context.Context, cfg *config.Config, orgNamespacePrefix string) (*openbao.Store, error) {
	httpClient, err := httpClientWithCA(cfg.OpenBaoTimeout, cfg.OpenBaoCACertFile, "OPENBAO_CA_CERT_FILE")
	if err != nil {
		return nil, err
	}

	var auth openbao.Auth
	switch cfg.OpenBaoAuth {
	case "approle":
		auth = openbao.AppRoleAuth{Mount: cfg.OpenBaoAuthMount, RoleIDFile: cfg.OpenBaoAppRoleRoleIDFile, SecretIDFile: cfg.OpenBaoAppRoleSecretIDFile}
	case "token":
		auth = openbao.TokenAuth{TokenFile: cfg.OpenBaoTokenFile}
	default:
		auth = openbao.KubernetesAuth{Mount: cfg.OpenBaoAuthMount, Role: cfg.OpenBaoRole, TokenFile: cfg.OpenBaoKubernetesTokenFile}
	}
	client, err := openbao.NewClient(openbao.ClientConfig{
		Address: cfg.OpenBaoAddr, Namespace: cfg.OpenBaoNamespace, Auth: auth, HTTPClient: httpClient,
	})
	if err != nil {
		return nil, err
	}
	var options []openbao.Option
	if orgNamespacePrefix != "" {
		options = append(options, openbao.WithOrgNamespaces(orgNamespacePrefix))
	}
	store, err := openbao.New(client, cfg.OpenBaoMount, cfg.OpenBaoPathPrefix, options...)
	if err != nil {
		return nil, err
	}

	checkCtx, cancel := context.WithTimeout(ctx, openBaoCheckTimeout)
	defer cancel()
	if err := store.Check(checkCtx); err != nil {
		slog.Warn("OpenBao secret store not usable yet; Secret values cannot be read or written until it is",
			"address", cfg.OpenBaoAddr, "mount", cfg.OpenBaoMount, "auth", cfg.OpenBaoAuth,
			"org_namespace_prefix", orgNamespacePrefix, "error", err)
	} else {
		slog.Info("OpenBao secret store ready", "address", cfg.OpenBaoAddr, "mount", cfg.OpenBaoMount, "prefix", cfg.OpenBaoPathPrefix,
			"org_namespace_prefix", orgNamespacePrefix)
	}
	return store, nil
}

// secretLister lists Secret metadata rows.
type secretLister interface {
	List(ctx context.Context, opts v1alpha1store.ListOpts) ([]*v1alpha1.RawObject, string, error)
}

// migrationResult counts what migrateSecretPayloads did.
type migrationResult struct {
	Copied, Present, Missing, Failed int
}

// migrateSecretPayloads copies each Secret's payload from `from` to `to`
// when `to` does not have it yet, and verifies the copy. It never deletes
// from `from`, and running it again copies nothing twice. Every replica may
// run it: a payload another replica copied first is simply present.
func migrateSecretPayloads(ctx context.Context, secrets secretLister, from, to secret.Store) (migrationResult, error) {
	var res migrationResult
	cursor := ""
	for {
		rows, next, err := secrets.List(ctx, v1alpha1store.ListOpts{Limit: migrationPageSize, Cursor: cursor})
		if err != nil {
			return res, fmt.Errorf("list Secrets: %w", err)
		}
		for _, row := range rows {
			ns, name := row.Metadata.Namespace, row.Metadata.Name
			log := slog.With("namespace", ns, "name", name)
			if _, err := to.Get(ctx, ns, name); err == nil {
				res.Present++
				continue
			} else if !errors.Is(err, secret.ErrPayloadNotFound) {
				res.Failed++
				log.Error("secret migration: cannot read the target store", "error", err)
				continue
			}
			data, err := from.Get(ctx, ns, name)
			if errors.Is(err, secret.ErrPayloadNotFound) {
				res.Missing++
				log.Warn("secret migration: no payload in the source store")
				continue
			}
			if err != nil {
				res.Failed++
				log.Error("secret migration: cannot read the source store", "error", err)
				continue
			}
			if err := to.Put(ctx, ns, name, data); err != nil {
				res.Failed++
				log.Error("secret migration: cannot write the target store", "error", err)
				continue
			}
			copied, err := to.Get(ctx, ns, name)
			if err != nil || !samePayload(data, copied) {
				res.Failed++
				log.Error("secret migration: the copy does not match", "error", err)
				continue
			}
			res.Copied++
			log.Info("secret migration: payload copied")
		}
		if next == "" {
			return res, nil
		}
		cursor = next
	}
}

// migrateSecretPayloadsUntilDone runs migrateSecretPayloads until a pass
// completes with no failures, waiting firstWait before the second pass and
// doubling the wait up to maxWait. A failed read, write or list is retried
// rather than treated as final: a pass copies nothing twice, so payloads
// copied earlier count as present. It returns the last pass's result, or
// the context's error when ctx ends first.
func migrateSecretPayloadsUntilDone(ctx context.Context, secrets secretLister, from, to secret.Store, firstWait, maxWait time.Duration) (migrationResult, error) {
	wait := firstWait
	for pass := 1; ; pass++ {
		res, err := migrateSecretPayloads(ctx, secrets, from, to)
		if err == nil && res.Failed == 0 {
			return res, nil
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		slog.Warn("secret migration pass did not finish; retrying",
			"pass", pass, "copied", res.Copied, "already_present", res.Present, "missing_in_source", res.Missing,
			"failed", res.Failed, "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(wait):
		}
		wait = min(2*wait, maxWait)
	}
}

func samePayload(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || string(v) != string(w) {
			return false
		}
	}
	return true
}
