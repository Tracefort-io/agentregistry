package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
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
)

// buildOpenBaoStore returns the OpenBao payload store and checks, without
// failing startup, that it can log in and reach its mount: OpenBao may come
// up after the registry, and Secret reads and writes report the cause.
func buildOpenBaoStore(ctx context.Context, cfg *config.Config) (*openbao.Store, error) {
	httpClient := &http.Client{Timeout: cfg.OpenBaoTimeout}
	if cfg.OpenBaoCACertFile != "" {
		pem, err := os.ReadFile(cfg.OpenBaoCACertFile)
		if err != nil {
			return nil, fmt.Errorf("read OPENBAO_CA_CERT_FILE: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("OPENBAO_CA_CERT_FILE %s holds no PEM certificates", cfg.OpenBaoCACertFile)
		}
		httpClient.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		}
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
	store, err := openbao.New(client, cfg.OpenBaoMount, cfg.OpenBaoPathPrefix)
	if err != nil {
		return nil, err
	}

	checkCtx, cancel := context.WithTimeout(ctx, openBaoCheckTimeout)
	defer cancel()
	if err := store.Check(checkCtx); err != nil {
		slog.Warn("OpenBao secret store not usable yet; Secret values cannot be read or written until it is",
			"address", cfg.OpenBaoAddr, "mount", cfg.OpenBaoMount, "auth", cfg.OpenBaoAuth, "error", err)
	} else {
		slog.Info("OpenBao secret store ready", "address", cfg.OpenBaoAddr, "mount", cfg.OpenBaoMount, "prefix", cfg.OpenBaoPathPrefix)
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
