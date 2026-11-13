-- Changes held for approval. The access request itself (workflow,
-- approvers, decisions) lives in the AuthZEN PDP's access request service;
-- this table keeps what the registry needs to apply the change once it is
-- approved: the document, the requester and the outcome.
CREATE TABLE IF NOT EXISTS approval_requests (
    id                 TEXT PRIMARY KEY,           -- the PDP's task id (arq_...)
    status             TEXT        NOT NULL,
    verb               TEXT        NOT NULL,       -- apply | delete
    kind               TEXT        NOT NULL,
    namespace          TEXT        NOT NULL,
    name               TEXT        NOT NULL,
    tag                TEXT        NOT NULL DEFAULT '',
    document           JSONB,                       -- the document to apply; NULL for a delete
    document_sha256    TEXT        NOT NULL DEFAULT '',
    requester          JSONB       NOT NULL,        -- the requester's identity, to re-evaluate as them
    requester_subject  TEXT        NOT NULL,
    requester_username TEXT        NOT NULL DEFAULT '',
    status_endpoint    TEXT        NOT NULL,
    approval_id        TEXT        NOT NULL DEFAULT '',
    detail             TEXT        NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS approval_requests_status_idx ON approval_requests (status, updated_at);
CREATE INDEX IF NOT EXISTS approval_requests_requester_idx ON approval_requests (requester_subject, created_at);
