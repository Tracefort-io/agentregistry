package v1alpha1store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	pkgdb "github.com/agentregistry-dev/agentregistry/pkg/registry/database"
)

// Version statuses of tagged artifacts, the MCP Registry API's values. A
// version with no status change recorded is active.
const (
	VersionStatusActive     = "active"
	VersionStatusDeprecated = "deprecated"
	VersionStatusDeleted    = "deleted"
)

// versionStatusEventsTable keeps every status change of a tagged version
// (migration 019). It is append-only.
const versionStatusEventsTable = "version_status_events"

// ErrVersionDeleted reports a read of a tagged version that was deleted. The
// version is kept, with its history, but no longer served; the error also
// matches pkgdb.ErrNotFound.
var ErrVersionDeleted error = versionDeletedError{}

type versionDeletedError struct{}

func (versionDeletedError) Error() string { return "v1alpha1 store: version was deleted" }

func (versionDeletedError) Is(target error) bool { return target == pkgdb.ErrNotFound }

// ErrTagDeleted reports an apply to a tag whose version was deleted.
// Versions are immutable, so a deleted tag cannot be applied again; new
// content takes a new tag.
var ErrTagDeleted = errors.New("v1alpha1 store: tag was deleted; versions are immutable, apply a new tag")

// StatusChange is who changed a version's status, as recorded in its
// history: the caller, the approval the change was made under, if any, and
// the request.
type StatusChange struct {
	ActorSubject  string
	ActorIssuer   string
	ActorUsername string
	ApprovalID    string
	RequestID     string
}

// DeleteVersions marks tagged versions deleted: tag's version, or every live
// tag of (namespace, name) when tag is empty. Each version's row is kept and
// a "deleted" status change is appended to its history, in one transaction.
// Returns pkgdb.ErrNotFound when no live version matches.
func (s *Store) DeleteVersions(ctx context.Context, namespace, name, tag string, change StatusChange) error {
	if s.behavior != TaggedArtifactStore {
		return errors.New("v1alpha1 store: DeleteVersions is only supported on tagged-artifact stores")
	}
	if namespace == "" || name == "" {
		return errors.New("v1alpha1 store: namespace and name are required")
	}
	return runInTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Serialize with applies of the same name (upsertTagged takes the
		// same lock), so a delete and an apply of one tag cannot interleave.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, s.advisoryLockKey(s.table, namespace, name)); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}
		rows, err := tx.Query(ctx,
			fmt.Sprintf(`
				UPDATE %s SET deletion_timestamp = NOW()
				WHERE namespace=$1 AND name=$2 AND ($3 = '' OR tag=$3) AND deletion_timestamp IS NULL
				RETURNING tag`, s.qualified),
			namespace, name, tag)
		if err != nil {
			return fmt.Errorf("mark deleted: %w", err)
		}
		tags, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("mark deleted: %w", err)
		}
		if len(tags) == 0 {
			return pkgdb.ErrNotFound
		}
		if _, err := tx.Exec(ctx,
			fmt.Sprintf(`
				INSERT INTO %s (resource_table, namespace, name, tag, previous_status, status,
				                actor_subject, actor_issuer, actor_username, approval_id, request_id)
				SELECT $1, $2, $3, t, $5, $6, $7, $8, $9, $10, $11 FROM unnest($4::text[]) AS t`, s.events),
			s.table, namespace, name, tags, VersionStatusActive, VersionStatusDeleted,
			change.ActorSubject, change.ActorIssuer, change.ActorUsername, change.ApprovalID, change.RequestID); err != nil {
			return fmt.Errorf("record status change: %w", err)
		}
		return nil
	})
}

// VersionStatusEvent is one entry of a version's status history.
type VersionStatusEvent struct {
	PreviousStatus string
	Status         string
	StatusChange
}

// VersionStatusHistory returns a tagged version's status changes, oldest
// first. An empty history means the version is active.
func (s *Store) VersionStatusHistory(ctx context.Context, namespace, name, tag string) ([]VersionStatusEvent, error) {
	if s.behavior != TaggedArtifactStore {
		return nil, errors.New("v1alpha1 store: VersionStatusHistory is only supported on tagged-artifact stores")
	}
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`
			SELECT previous_status, status, actor_subject, actor_issuer, actor_username, approval_id, request_id
			FROM %s
			WHERE resource_table=$1 AND namespace=$2 AND name=$3 AND tag=$4
			ORDER BY id`, s.events),
		s.table, namespace, name, tag)
	if err != nil {
		return nil, fmt.Errorf("version status history: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (VersionStatusEvent, error) {
		var e VersionStatusEvent
		err := row.Scan(&e.PreviousStatus, &e.Status, &e.ActorSubject, &e.ActorIssuer, &e.ActorUsername, &e.ApprovalID, &e.RequestID)
		return e, err
	})
}
