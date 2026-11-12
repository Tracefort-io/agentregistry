package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/agentregistry-dev/agentregistry/internal/registry/config"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	pkgdb "github.com/agentregistry-dev/agentregistry/pkg/registry/database"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

var auditLogger = logging.New("audit")

const (
	auditRetentionInterval = time.Hour
	auditPruneBatch        = 1000
)

// auditWiring is the audit log as configured: the recorder the API and the
// PEP write to, and the store GET /v0/audit reads.
type auditWiring struct {
	recorder audit.Recorder
	lister   audit.Lister
	shutdown func(context.Context) error
}

// auditPruner deletes events past retention.
type auditPruner interface {
	PruneAuditEventsBefore(ctx context.Context, before time.Time, limit int) (int64, error)
}

// buildAudit sets up the audit log. extra (AppOptions.AuditRecorder)
// receives every event as well, even with the built-in log disabled.
func buildAudit(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, extra audit.Recorder) (auditWiring, error) {
	w := auditWiring{recorder: extra, shutdown: func(context.Context) error { return nil }}
	if !cfg.AuditEnabled {
		auditLogger.Info("audit log disabled")
		return w, nil
	}
	store := v1alpha1store.NewAuditEventStore(pool, pkgdb.OSSSchemaRegistry().MustGet(pkgdb.OSSSourceName))
	recorders := []audit.Recorder{audit.StoreRecorder(store, auditLogger), extra}

	if cfg.AuditOTLP {
		// Endpoint, headers and TLS come from OTEL_EXPORTER_OTLP_*.
		exporter, err := otlploghttp.New(ctx)
		if err != nil {
			return auditWiring{}, fmt.Errorf("create OTLP audit exporter: %w", err)
		}
		provider := sdklog.NewLoggerProvider(
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
			sdklog.WithResource(resource.NewWithAttributes(semconv.SchemaURL,
				semconv.ServiceName("agentregistry"), semconv.ServiceVersion(cfg.Version))),
		)
		recorders = append(recorders, audit.OTelRecorder(provider.Logger("github.com/agentregistry-dev/agentregistry/audit")))
		w.shutdown = provider.Shutdown
		auditLogger.Info("audit events exported over OTLP")
	}

	w.recorder = audit.Multi(recorders...)
	w.lister = store
	if cfg.AuditRetention > 0 {
		go runAuditRetention(ctx, store, cfg.AuditRetention, auditRetentionInterval, time.Now)
	}
	auditLogger.Info("audit log enabled", "retention", cfg.AuditRetention.String())
	return w, nil
}

// runAuditRetention deletes events older than retention now and then every
// interval, until ctx ends. Every replica may run it; deletes are idempotent.
func runAuditRetention(ctx context.Context, store auditPruner, retention, interval time.Duration, now func() time.Time) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		pruneAudit(ctx, store, now().Add(-retention))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pruneAudit deletes in batches so one pass never holds a long lock.
func pruneAudit(ctx context.Context, store auditPruner, before time.Time) int64 {
	var total int64
	for ctx.Err() == nil {
		n, err := store.PruneAuditEventsBefore(ctx, before, auditPruneBatch)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				auditLogger.Error("audit retention failed", "error", err)
			}
			break
		}
		total += n
		if n < auditPruneBatch {
			break
		}
	}
	if total > 0 {
		auditLogger.Info("audit events past retention deleted", "count", total, "before", before)
	}
	return total
}
