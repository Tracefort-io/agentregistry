-- Workload identities of Deployments. A runtime that gives a Deployment's
-- workload a SPIFFE identity records the agent's SPIFFE ID prefix here when
-- it assigns it, and again when it revokes it. The prefix contains the
-- Deployment's UID, so it belongs to one Deployment for ever, and every
-- replica's full ID (prefix + instance/<pod UID>) to one pod.
--
-- SPIFFE IDs are never reused: a prefix can be assigned once, ever
-- (deployment_identity_events_assigned_once), even after it is revoked, and
-- revoked once (deployment_identity_events_revoked_once). A Deployment keeps
-- its identity while undeployed; it is revoked when the Deployment is
-- deleted or moves to another agent.
-- Append-only: rows are never updated or deleted, so the history answers
-- which Deployment and agent version held an identity at any time.
CREATE TABLE IF NOT EXISTS deployment_identity_events (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event                TEXT        NOT NULL CHECK (event IN ('assigned', 'revoked')),
    spiffe_id_prefix     TEXT        NOT NULL CHECK (spiffe_id_prefix LIKE 'spiffe://%/'),
    deployment_namespace TEXT        NOT NULL,
    deployment_name      TEXT        NOT NULL,
    deployment_uid       UUID        NOT NULL,
    agent_namespace      TEXT        NOT NULL,
    agent_name           TEXT        NOT NULL,
    agent_tag            TEXT        NOT NULL DEFAULT '',
    runtime_namespace    TEXT        NOT NULL,
    runtime_name         TEXT        NOT NULL,
    workload_namespace   TEXT        NOT NULL,
    workload_name        TEXT        NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS deployment_identity_events_assigned_once
    ON deployment_identity_events (spiffe_id_prefix) WHERE event = 'assigned';
CREATE UNIQUE INDEX IF NOT EXISTS deployment_identity_events_revoked_once
    ON deployment_identity_events (spiffe_id_prefix) WHERE event = 'revoked';
CREATE INDEX IF NOT EXISTS deployment_identity_events_prefix_idx
    ON deployment_identity_events (spiffe_id_prefix, id);
CREATE INDEX IF NOT EXISTS deployment_identity_events_deployment_idx
    ON deployment_identity_events (deployment_uid, id);

CREATE OR REPLACE FUNCTION deployment_identity_events_append_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'deployment_identity_events is append-only';
END
$$;

CREATE OR REPLACE TRIGGER deployment_identity_events_no_update
    BEFORE UPDATE OR DELETE ON deployment_identity_events
    FOR EACH ROW EXECUTE FUNCTION deployment_identity_events_append_only();
CREATE OR REPLACE TRIGGER deployment_identity_events_no_truncate
    BEFORE TRUNCATE ON deployment_identity_events
    FOR EACH STATEMENT EXECUTE FUNCTION deployment_identity_events_append_only();
