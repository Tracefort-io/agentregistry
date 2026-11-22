-- Status history of tagged versions (agents, mcp_servers, skills, prompts,
-- models, plugins). Registry records are immutable: a version's content is
-- never changed or removed, and a status change (MCP Registry API values:
-- active, deprecated, deleted) is appended here. A version with no entry is
-- active; its current status is its latest entry. The version row's
-- deletion_timestamp is set with the "deleted" entry, so reads can hide it.
-- Append-only: rows are never updated or deleted.
CREATE TABLE IF NOT EXISTS version_status_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resource_table  TEXT        NOT NULL,
    namespace       TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    tag             TEXT        NOT NULL,
    previous_status TEXT        NOT NULL CHECK (previous_status IN ('active', 'deprecated', 'deleted')),
    status          TEXT        NOT NULL CHECK (status IN ('active', 'deprecated', 'deleted')),
    actor_subject   TEXT        NOT NULL DEFAULT '',
    actor_issuer    TEXT        NOT NULL DEFAULT '',
    actor_username  TEXT        NOT NULL DEFAULT '',
    approval_id     TEXT        NOT NULL DEFAULT '',
    request_id      TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS version_status_events_version_idx
    ON version_status_events (resource_table, namespace, name, tag, id);

CREATE OR REPLACE FUNCTION version_status_events_append_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'version_status_events is append-only';
END
$$;

CREATE OR REPLACE TRIGGER version_status_events_no_update
    BEFORE UPDATE OR DELETE ON version_status_events
    FOR EACH ROW EXECUTE FUNCTION version_status_events_append_only();
CREATE OR REPLACE TRIGGER version_status_events_no_truncate
    BEFORE TRUNCATE ON version_status_events
    FOR EACH STATEMENT EXECUTE FUNCTION version_status_events_append_only();
