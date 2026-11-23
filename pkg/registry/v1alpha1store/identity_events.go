package v1alpha1store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// deploymentIdentityEventsTable keeps the assignment and revocation of
// Deployments' workload identities (migration 020). It is append-only, and a
// SPIFFE ID prefix can be assigned once and revoked once, ever.
const deploymentIdentityEventsTable = "deployment_identity_events"

// Identity events.
const (
	IdentityAssigned = "assigned"
	IdentityRevoked  = "revoked"
)

// ErrIdentityAlreadyAssigned reports an assignment of a SPIFFE ID prefix
// that was assigned before. SPIFFE IDs are never reused, even after
// revocation.
var ErrIdentityAlreadyAssigned = errors.New("v1alpha1 store: SPIFFE ID prefix was already assigned; identities are never reused")

const identityAssignedOnceIndex = "deployment_identity_events_assigned_once"

// IdentityEvent is one assignment or revocation of a Deployment's workload
// identity.
type IdentityEvent struct {
	Event               string
	SPIFFEIDPrefix      string
	DeploymentNamespace string
	DeploymentName      string
	DeploymentUID       string
	AgentNamespace      string
	AgentName           string
	AgentTag            string
	RuntimeNamespace    string
	RuntimeName         string
	WorkloadNamespace   string
	WorkloadName        string
	// OccurredAt is set on reads; the database sets it on insert.
	OccurredAt time.Time
}

// IdentityChange is what ApplyPatchWithIdentityChange records: the prefixes
// to revoke, then the one to assign (Event is set to IdentityAssigned).
type IdentityChange struct {
	Revoke []string
	Assign *IdentityEvent
}

// ApplyPatchWithIdentityChange applies patch and internalMeta to the row and
// records change, in one transaction, so a Deployment's recorded identity and
// its history never disagree. A revocation copies the details of the
// prefix's assignment; revoking a prefix that was never assigned, or was
// already revoked, records nothing. Assigning a prefix assigned before fails
// with ErrIdentityAlreadyAssigned, and nothing is written.
func (s *Store) ApplyPatchWithIdentityChange(ctx context.Context, namespace, name string, patch PatchOpts, internalMeta any, change IdentityChange) error {
	if s.behavior != MutableObjectStore || !s.internalMeta {
		return errors.New("v1alpha1 store: identity events are only supported on stores with internal meta")
	}
	if internalMeta == nil {
		return errors.New("v1alpha1 store: internal meta must not be nil")
	}
	return runInTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.applyPatchTx(ctx, tx, namespace, name, "", patch, internalMeta); err != nil {
			return err
		}
		for _, prefix := range change.Revoke {
			if _, err := tx.Exec(ctx,
				fmt.Sprintf(`
					INSERT INTO %[1]s (event, spiffe_id_prefix, deployment_namespace, deployment_name, deployment_uid,
					                   agent_namespace, agent_name, agent_tag, runtime_namespace, runtime_name,
					                   workload_namespace, workload_name)
					SELECT 'revoked', spiffe_id_prefix, deployment_namespace, deployment_name, deployment_uid,
					       agent_namespace, agent_name, agent_tag, runtime_namespace, runtime_name,
					       workload_namespace, workload_name
					FROM %[1]s WHERE spiffe_id_prefix=$1 AND event='assigned'
					ON CONFLICT (spiffe_id_prefix) WHERE event='revoked' DO NOTHING`, s.identityEvents),
				prefix); err != nil {
				return fmt.Errorf("record identity revocation: %w", err)
			}
		}
		if e := change.Assign; e != nil {
			if _, err := tx.Exec(ctx,
				fmt.Sprintf(`
					INSERT INTO %s (event, spiffe_id_prefix, deployment_namespace, deployment_name, deployment_uid,
					                agent_namespace, agent_name, agent_tag, runtime_namespace, runtime_name,
					                workload_namespace, workload_name)
					VALUES ('assigned', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, s.identityEvents),
				e.SPIFFEIDPrefix, e.DeploymentNamespace, e.DeploymentName, e.DeploymentUID,
				e.AgentNamespace, e.AgentName, e.AgentTag, e.RuntimeNamespace, e.RuntimeName,
				e.WorkloadNamespace, e.WorkloadName); err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == identityAssignedOnceIndex {
					return fmt.Errorf("%w: %s", ErrIdentityAlreadyAssigned, e.SPIFFEIDPrefix)
				}
				return fmt.Errorf("record identity assignment: %w", err)
			}
		}
		return nil
	})
}

// RevokedIdentities returns which of prefixes were revoked. A revoked prefix
// is never valid again, whatever else still names it.
func (s *Store) RevokedIdentities(ctx context.Context, prefixes []string) (map[string]bool, error) {
	if s.behavior != MutableObjectStore || !s.internalMeta {
		return nil, errors.New("v1alpha1 store: identity events are only supported on stores with internal meta")
	}
	revoked := map[string]bool{}
	if len(prefixes) == 0 {
		return revoked, nil
	}
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT spiffe_id_prefix FROM %s WHERE event='revoked' AND spiffe_id_prefix = ANY($1)`, s.identityEvents),
		prefixes)
	if err != nil {
		return nil, fmt.Errorf("revoked identities: %w", err)
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("revoked identities: %w", err)
	}
	for _, prefix := range found {
		revoked[prefix] = true
	}
	return revoked, nil
}

// IdentityHistory returns the identity events of a SPIFFE ID prefix, oldest
// first: who held it, and from when until when.
func (s *Store) IdentityHistory(ctx context.Context, spiffeIDPrefix string) ([]IdentityEvent, error) {
	if s.behavior != MutableObjectStore || !s.internalMeta {
		return nil, errors.New("v1alpha1 store: identity events are only supported on stores with internal meta")
	}
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`
			SELECT event, spiffe_id_prefix, deployment_namespace, deployment_name, deployment_uid::text,
			       agent_namespace, agent_name, agent_tag, runtime_namespace, runtime_name,
			       workload_namespace, workload_name, occurred_at
			FROM %s WHERE spiffe_id_prefix=$1 ORDER BY id`, s.identityEvents),
		spiffeIDPrefix)
	if err != nil {
		return nil, fmt.Errorf("identity history: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (IdentityEvent, error) {
		var e IdentityEvent
		err := row.Scan(&e.Event, &e.SPIFFEIDPrefix, &e.DeploymentNamespace, &e.DeploymentName, &e.DeploymentUID,
			&e.AgentNamespace, &e.AgentName, &e.AgentTag, &e.RuntimeNamespace, &e.RuntimeName,
			&e.WorkloadNamespace, &e.WorkloadName, &e.OccurredAt)
		return e, err
	})
}
