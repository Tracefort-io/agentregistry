package v1alpha1store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pkgdb "github.com/agentregistry-dev/agentregistry/pkg/registry/database"
)

// Approval request states. pending → approved → applying → applied|failed|stale,
// or pending → denied|expired|cancelled.
const (
	ApprovalPending   = "pending"
	ApprovalApproved  = "approved"
	ApprovalApplying  = "applying"
	ApprovalApplied   = "applied"
	ApprovalFailed    = "failed"
	ApprovalStale     = "stale"
	ApprovalDenied    = "denied"
	ApprovalExpired   = "expired"
	ApprovalCancelled = "cancelled"
)

// ApprovalRequest is a change held for approval.
type ApprovalRequest struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Verb      string `json:"verb"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Tag       string `json:"tag,omitempty"`
	// Document is the document to apply; nil for a delete.
	Document       json.RawMessage `json:"document,omitempty"`
	DocumentSHA256 string          `json:"documentSha256,omitempty"`
	// Requester is the requester's identity, kept to re-evaluate the
	// change as them once it is approved.
	Requester         json.RawMessage `json:"-"`
	RequesterSubject  string          `json:"requesterSubject"`
	RequesterUsername string          `json:"requesterUsername,omitempty"`
	StatusEndpoint    string          `json:"-"`
	ApprovalID        string          `json:"approvalId,omitempty"`
	// Detail is why it failed, was denied or went stale, or how it applied.
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ApprovalQuery selects approval requests, newest first.
type ApprovalQuery struct {
	RequesterSubject string
	Statuses         []string
	Limit            int
	Cursor           string
}

// ErrApprovalNotFound is an unknown approval request.
var ErrApprovalNotFound = errors.New("approval request not found")

// ApprovalRequestStore keeps approval requests.
type ApprovalRequestStore struct {
	pool      *pgxpool.Pool
	qualified string
}

// NewApprovalRequestStore constructs the store.
func NewApprovalRequestStore(pool *pgxpool.Pool, schema pkgdb.Schema) *ApprovalRequestStore {
	return &ApprovalRequestStore{pool: pool, qualified: schema.Qualify("approval_requests")}
}

const approvalColumns = `id, status, verb, kind, namespace, name, tag, document, document_sha256, requester,
	requester_subject, requester_username, status_endpoint, approval_id, detail, created_at, updated_at`

// CreateApprovalRequest stores r as pending.
func (s *ApprovalRequestStore) CreateApprovalRequest(ctx context.Context, r ApprovalRequest) error {
	var doc any
	if len(r.Document) > 0 {
		doc = r.Document
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO `+s.qualified+` (id, status, verb, kind, namespace, name, tag, document,
		document_sha256, requester, requester_subject, requester_username, status_endpoint)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		r.ID, ApprovalPending, r.Verb, r.Kind, r.Namespace, r.Name, r.Tag, doc,
		r.DocumentSHA256, r.Requester, r.RequesterSubject, r.RequesterUsername, r.StatusEndpoint)
	if err != nil {
		return fmt.Errorf("create approval request: %w", err)
	}
	return nil
}

// GetApprovalRequest returns one request.
func (s *ApprovalRequestStore) GetApprovalRequest(ctx context.Context, id string) (ApprovalRequest, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+approvalColumns+` FROM `+s.qualified+` WHERE id = $1`, id)
	r, err := scanApproval(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApprovalRequest{}, ErrApprovalNotFound
	}
	return r, err
}

// ListApprovalRequests returns requests matching q, newest first, and a
// cursor for the next page.
func (s *ApprovalRequestStore) ListApprovalRequests(ctx context.Context, q ApprovalQuery) ([]ApprovalRequest, string, error) {
	limit := q.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if q.RequesterSubject != "" {
		where = append(where, "requester_subject = "+arg(q.RequesterSubject))
	}
	if len(q.Statuses) > 0 {
		where = append(where, "status = ANY("+arg(q.Statuses)+")")
	}
	if q.Cursor != "" {
		at, id, err := decodeApprovalCursor(q.Cursor)
		if err != nil {
			return nil, "", err
		}
		where = append(where, "(created_at, id) < ("+arg(at)+", "+arg(id)+")")
	}
	query := `SELECT ` + approvalColumns + ` FROM ` + s.qualified
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT " + arg(limit+1)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list approval requests: %w", err)
	}
	defer rows.Close()
	var out []ApprovalRequest
	for rows.Next() {
		r, err := scanApproval(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("read approval requests: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = encodeApprovalCursor(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

// TransitionApprovalRequest moves request id from one of `from` to `to`,
// setting approval_id and detail when given. It reports false when the
// request was not in one of `from`, so only one replica wins a transition.
func (s *ApprovalRequestStore) TransitionApprovalRequest(ctx context.Context, id string, from []string, to, approvalID, detail string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.qualified+` SET status = $3,
		approval_id = CASE WHEN $4 = '' THEN approval_id ELSE $4 END,
		detail = CASE WHEN $5 = '' THEN detail ELSE $5 END,
		updated_at = NOW()
		WHERE id = $1 AND status = ANY($2)`, id, from, to, approvalID, detail)
	if err != nil {
		return false, fmt.Errorf("update approval request %s: %w", id, err)
	}
	return tag.RowsAffected() == 1, nil
}

// StuckApplyingBefore lists requests left applying since before t, as a
// replica that stopped mid-apply leaves them.
func (s *ApprovalRequestStore) StuckApplyingBefore(ctx context.Context, t time.Time, limit int) ([]ApprovalRequest, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+approvalColumns+` FROM `+s.qualified+`
		WHERE status = $1 AND updated_at < $2 ORDER BY updated_at LIMIT $3`, ApprovalApplying, t, limit)
	if err != nil {
		return nil, fmt.Errorf("list stuck approval requests: %w", err)
	}
	defer rows.Close()
	var out []ApprovalRequest
	for rows.Next() {
		r, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanApproval(row pgx.Row) (ApprovalRequest, error) {
	var r ApprovalRequest
	var doc, requester []byte
	err := row.Scan(&r.ID, &r.Status, &r.Verb, &r.Kind, &r.Namespace, &r.Name, &r.Tag, &doc, &r.DocumentSHA256,
		&requester, &r.RequesterSubject, &r.RequesterUsername, &r.StatusEndpoint, &r.ApprovalID, &r.Detail,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, err
		}
		return r, fmt.Errorf("scan approval request: %w", err)
	}
	if len(doc) > 0 {
		r.Document = doc
	}
	r.Requester = requester
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return r, nil
}

func encodeApprovalCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.Format(time.RFC3339Nano) + "|" + id))
}

func decodeApprovalCursor(c string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	at, id, ok := strings.Cut(string(raw), "|")
	t, err := time.Parse(time.RFC3339Nano, at)
	if !ok || err != nil || id == "" {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	return t, id, nil
}
