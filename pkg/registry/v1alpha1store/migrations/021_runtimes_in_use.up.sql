-- A Runtime row cannot be removed while a Deployment still references it,
-- including a terminating one: tearing down a Deployment's workload needs its
-- Runtime to select and configure the provider. Removing the Runtime first
-- used to finalize the Deployment without removing its workload, leaving it
-- running (and holding any identity it was given) with no registry record.
-- Delete the Deployments first; the Runtime can go once they are purged.
--
-- Only the removal of the row is refused. A Runtime with finalizers may
-- still be marked terminating: it stays readable, and its Deployments' teardown
-- uses it. Discovered Deployments (annotation agentregistry.solo.io/origin:
-- discovered) are observations of workloads the registry doesn't run; they
-- don't hold a Runtime, and discovery removes them once it is gone.
--
-- Enforced here so every delete path (per-kind, batch apply, CLI) is
-- covered. deployments is qualified with the trigger's own schema, so the
-- check doesn't depend on the session's search_path. The annotation key is
-- spelled in two parts only because the migration lint reads its prefix
-- followed by a dot as a schema name.
CREATE OR REPLACE FUNCTION runtimes_refuse_delete_in_use() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    referencing TEXT;
BEGIN
    EXECUTE format(
        'SELECT string_agg(d.namespace || ''/'' || d.name, '', '' ORDER BY d.namespace, d.name)
           FROM %I.deployments AS d
          WHERE d.spec->''runtimeRef''->>''name'' = $1
            AND COALESCE(NULLIF(d.spec->''runtimeRef''->>''namespace'', ''''), d.namespace) = $2
            AND d.annotations->>(''agentregistry'' || ''.solo.io/origin'') IS DISTINCT FROM ''discovered''',
        TG_TABLE_SCHEMA)
        INTO referencing
        USING OLD.name, OLD.namespace;
    IF referencing IS NOT NULL THEN
        RAISE EXCEPTION 'runtime %/% is still used by deployments %', OLD.namespace, OLD.name, referencing
            USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'runtimes_in_use';
    END IF;
    RETURN OLD;
END
$$;

CREATE OR REPLACE TRIGGER runtimes_in_use_no_delete
    BEFORE DELETE ON runtimes
    FOR EACH ROW EXECUTE FUNCTION runtimes_refuse_delete_in_use();
