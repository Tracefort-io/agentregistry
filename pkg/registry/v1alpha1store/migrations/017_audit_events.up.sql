-- Audit log: who applied or deleted what, and which reads were refused.
-- Append-only: rows are never updated, and are deleted only by retention.
CREATE TABLE IF NOT EXISTS audit_events (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at    TIMESTAMPTZ NOT NULL,
    request_id     TEXT        NOT NULL DEFAULT '',
    actor_subject  TEXT        NOT NULL DEFAULT '',
    actor_issuer   TEXT        NOT NULL DEFAULT '',
    actor_username TEXT        NOT NULL DEFAULT '',
    actor_client   BOOLEAN     NOT NULL DEFAULT FALSE,
    actor_via      TEXT[]      NOT NULL DEFAULT '{}',
    action         TEXT        NOT NULL,
    kind           TEXT        NOT NULL DEFAULT '',
    namespace      TEXT        NOT NULL DEFAULT '',
    name           TEXT        NOT NULL DEFAULT '',
    tag            TEXT        NOT NULL DEFAULT '',
    outcome        TEXT        NOT NULL,
    detail         TEXT        NOT NULL DEFAULT '',
    source         TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx ON audit_events (occurred_at);
CREATE INDEX IF NOT EXISTS audit_events_actor_subject_idx ON audit_events (actor_subject, id);
CREATE INDEX IF NOT EXISTS audit_events_actor_username_idx ON audit_events (actor_username, id);
CREATE INDEX IF NOT EXISTS audit_events_resource_idx ON audit_events (kind, namespace, name, id);

CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END
$$;

CREATE OR REPLACE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
CREATE OR REPLACE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
