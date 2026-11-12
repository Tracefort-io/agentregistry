package v1alpha1store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	pkgdb "github.com/agentregistry-dev/agentregistry/pkg/registry/database"
)

const (
	defaultAuditListLimit = 50
	maxAuditListLimit     = 500
	defaultAuditPruneMax  = 1000
)

// AuditEventStore keeps audit events in the append-only audit_events table.
type AuditEventStore struct {
	pool      *pgxpool.Pool
	qualified string
}

var (
	_ audit.Store  = (*AuditEventStore)(nil)
	_ audit.Lister = (*AuditEventStore)(nil)
)

// NewAuditEventStore constructs the audit event store.
func NewAuditEventStore(pool *pgxpool.Pool, schema pkgdb.Schema) *AuditEventStore {
	return &AuditEventStore{pool: pool, qualified: schema.Qualify("audit_events")}
}

// InsertAuditEvent stores e and returns its ID.
func (s *AuditEventStore) InsertAuditEvent(ctx context.Context, e audit.Event) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("v1alpha1 store: audit event store has nil pool")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	via := e.Actor.Via
	if via == nil {
		via = []string{}
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO `+s.qualified+` (
			occurred_at, request_id, actor_subject, actor_issuer, actor_username, actor_client, actor_via,
			action, kind, namespace, name, tag, outcome, detail, source
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id`,
		e.Time, e.RequestID, e.Actor.Subject, e.Actor.Issuer, e.Actor.Username, e.Actor.Client, via,
		e.Action, e.Resource.Kind, e.Resource.Namespace, e.Resource.Name, e.Resource.Tag,
		e.Outcome, e.Detail, e.Source,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert audit event: %w", err)
	}
	return id, nil
}

// ListAuditEvents returns events matching q, newest first, and a cursor for
// the next page ("" on the last page).
func (s *AuditEventStore) ListAuditEvents(ctx context.Context, q audit.Query) ([]audit.Event, string, error) {
	if s == nil || s.pool == nil {
		return nil, "", errors.New("v1alpha1 store: audit event store has nil pool")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultAuditListLimit
	}
	limit = min(limit, maxAuditListLimit)

	var where []string
	var args []any
	add := func(clause string, arg any) {
		args = append(args, arg)
		where = append(where, strings.ReplaceAll(clause, "?", "$"+strconv.Itoa(len(args))))
	}
	if q.Cursor != "" {
		before, err := decodeAuditCursor(q.Cursor)
		if err != nil {
			return nil, "", err
		}
		add("id < ?", before)
	}
	if q.Actor != "" {
		add("(actor_subject = ? OR actor_username = ?)", q.Actor)
	}
	for _, f := range []struct{ column, value string }{
		{"action", q.Action}, {"outcome", q.Outcome}, {"kind", q.Kind},
		{"namespace", q.Namespace}, {"name", q.Name},
	} {
		if f.value != "" {
			add(f.column+" = ?", f.value)
		}
	}
	if !q.Since.IsZero() {
		add("occurred_at >= ?", q.Since)
	}
	if !q.Until.IsZero() {
		add("occurred_at < ?", q.Until)
	}
	query := `
		SELECT id, occurred_at, request_id, actor_subject, actor_issuer, actor_username, actor_client, actor_via,
			action, kind, namespace, name, tag, outcome, detail, source
		FROM ` + s.qualified
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit+1)
	query += " ORDER BY id DESC LIMIT $" + strconv.Itoa(len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	events := make([]audit.Event, 0, limit)
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, "", err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("read audit events: %w", err)
	}
	next := ""
	if len(events) > limit {
		events = events[:limit]
		next = encodeAuditCursor(events[limit-1].ID)
	}
	return events, next, nil
}

// PruneAuditEventsBefore deletes up to limit events older than before and
// returns how many it deleted.
func (s *AuditEventStore) PruneAuditEventsBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("v1alpha1 store: audit event store has nil pool")
	}
	if limit <= 0 {
		limit = defaultAuditPruneMax
	}
	tag, err := s.pool.Exec(ctx, `
		WITH doomed AS (
			SELECT id FROM `+s.qualified+`
			WHERE occurred_at < $1
			ORDER BY id
			LIMIT $2
		)
		DELETE FROM `+s.qualified+` a USING doomed WHERE a.id = doomed.id`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanAuditEvent(row pgx.Row) (audit.Event, error) {
	var e audit.Event
	if err := row.Scan(
		&e.ID, &e.Time, &e.RequestID,
		&e.Actor.Subject, &e.Actor.Issuer, &e.Actor.Username, &e.Actor.Client, &e.Actor.Via,
		&e.Action, &e.Resource.Kind, &e.Resource.Namespace, &e.Resource.Name, &e.Resource.Tag,
		&e.Outcome, &e.Detail, &e.Source,
	); err != nil {
		return audit.Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	e.Time = e.Time.UTC()
	if len(e.Actor.Via) == 0 {
		e.Actor.Via = nil
	}
	return e, nil
}

func encodeAuditCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

func decodeAuditCursor(cursor string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, audit.ErrInvalidCursor
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, audit.ErrInvalidCursor
	}
	return id, nil
}
