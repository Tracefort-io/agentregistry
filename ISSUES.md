# Pending issues

Open work and known problems in this repository. Remove an entry when it's fixed, and say in the commit which one it closes. Last updated 2026-11-19.

## In progress

### 1. Approval workflows for publish and deploy: known flaws and gaps

Approvals ([docs/approvals.md](docs/approvals.md)) run on the k3s cluster: opa-authzen-plugin built from its main branch hosts the access request service, and the approval rules are in the policy repository. The deployment is control-plane-prod's `16-approvals.sh`. Tested end to end through agentgateway on 2026-11-19:

- a writer's change is held; an approver approves it and the registry applies it, or denies it; the writer withdraws one; a writer's delete is held too;
- an approver can't decide their own change; a reader can't decide; an admin applies directly;
- the Approvals page in a browser, as the writer and the approver.

Not tested there: a held Deployment (Rego tests only), expiry after `task_ttl`, and an `out_of_scope` approval through the registry (unit tests and a local run against the PDP only). Callbacks are off, because the PDP only calls `https` URLs; the registry polls (`APPROVALS_POLL_INTERVAL`).

Known flaws:

- **Duplicated status:** the registry's `approval_requests` table keeps a copy of each request's status, which the access request service already tracks. The registry needs only the held document and the requester.
- **A decision in code, not Rego:** who may see or withdraw a held change under `/v0/approvals` (the requester or an admin) is decided in the registry's code, not by OPA (`ars_caller`).
- **Decisions missing from the audit log:** the registry records a held change (`request-approval`) and the approved apply, but not who approved, denied or withdrew it. The PDP records those as OpenTelemetry logs, which reach nothing unless it has an OTLP endpoint.
- **Reference policy's data path:** [approvals.rego](docs/auth/authzen/approvals.rego) reads `data.registry.*`, but a `data.json` in a policy repository's `authzen/` directory loads at `data.authzen.registry`. The deployed policy had to be adapted.

Not built yet:

- **Stale detection:** a live resource that changed between request and approval isn't detected; the reviewed document is applied over it.
- **No diff in the review:** the review page shows the submitted document, not a diff against the live resource.
- **Single-resource routes:** `PUT` and `DELETE` on a single resource don't hold changes; they answer `403 approval required`.
- **Static approvers:** approvers are a static list in policy data.
- **Notifications:** none, for example to Slack or Teams.

### 2. Rego policies: gaps

Policy authoring and publishing ([docs/policies.md](docs/policies.md)) runs on the k3s cluster against a GitHub repository, with OPAL loading merges into OPA (control-plane-prod's `12-policies.sh`). Tested end to end through agentgateway: a policy author publishes a pull request, it's merged on GitHub, the merge webhook tags the version (`authzen/v1` to `v4`), and OPAL loads it into OPA. The webhook reaches the registry through a named Cloudflare tunnel, which only passes `POST /policies/webhook`.

Not tested: GitLab.

Known flaws:

- **Versions list:** it shows the merge commit's message and author, not the pull request's title and author.

Not built yet:

- **Regal:** the editor reports compile errors only, not Regal's lint.
- **Root data:** a `data.json` at the repository root (loaded at `data`) belongs to no policy and can't be edited.
- **Rendered diffs:** versions show old and new files side by side, not a line diff.

## Bugs

### 3. A startup failure can hang without logging its error, and SIGTERM may not stop the process

When `registry.App` returns an error, or shuts down after SIGTERM, closing the database pool can wait forever for connections that background goroutines still hold: controllers, LISTEN subscriptions, loops on `context.Background()`. The error is never logged, and the pod stalls until its probe kills it.

It was seen twice: when a schema-name clash crashed route registration, and when a local registry ignored SIGTERM. A fix needs an app-scoped context, canceled before the pool closes, and the error logged before shutdown.

### 4. Tags aren't validated on apply

`metadata.tag: Bad Tag!` is accepted on `POST /v0/apply`, although the tag rule (`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`) forbids it. Names are validated; tags aren't.

## Gaps

### 5. Writes refused at the gateway aren't in the registry's audit log

agentgateway refuses some writes (for example, a reader's apply) before they reach the registry, so the registry can't record them. Only the gateway's logs have them.

### 6. Leader election

- **Lease expiry untested live:** a crashed Kubernetes Lease holder, where standbys wait out the 15s lease, wasn't tested on a cluster. Force-deleting a pod still sends SIGTERM, so the Lease was released, not expired.
- **No guard against mixed mechanisms:** replicas on `postgres` and `kubernetes` don't see each other, and changing the mechanism on a running system relies on stopping the old pods first.
- **No leader metric:** there's no `agentregistry_leader` metric yet; only logs show who leads.

### 7. Secrets

- **Database store:** it still encrypts with one static AES key, with no rotation. OpenBao option B, a Transit envelope with re-wrapping, isn't built.
- **OpenBao setup by hand:** for the OpenBao store, the setup (KV mount, policy, Kubernetes role) is done by hand from [docs/secrets-openbao.md](docs/secrets-openbao.md).

### 8. HTTP hardening

The web UI's Content-Security-Policy allows `'unsafe-inline'` scripts, because Next.js inlines its bootstrap code. Nonces or hashes would remove that.

### 9. Identity

Only Keycloak has been tested; Entra ID hasn't. [test/authe2e](test/authe2e/README.md) shows how to run the per-role test with Entra tokens.

## Code health

### 10. Lint and type errors in older code

- **Integration-tagged tests:** `golangci-lint` with `--build-tags=integration` reports findings in older tests (`sort` imports, loops that could range over int, testify assertions), for example `store_tagging_test.go`, `store_test.go`, `adapter_resolver_test.go` and `predicate_integration_test.go`.
- **UI type check:** `npx tsc --noEmit` fails in `ui/components/__tests__/server-card.test.tsx` (`repository` isn't on `McpServerSource`).
- **UI lint:** ESLint warns about a missing `fetchData` dependency in `ui/app/page.tsx`.

### 11. Tooling

- **Go version:** with Go 1.27 installed, the pinned golangci-lint can't read the standard library. Run `GOTOOLCHAIN=go1.26.9 make lint`.
- **Network-dependent test:** `TestValidateNPM_RealPackages` calls the real npm registry and fails when DNS or the network is unavailable.

## Roadmap

### 12. Features not started

- **Runtimes:** AgentCore and Virtual.
- **Gateway binding:** publish a deployed agent or MCP server through agentgateway.
- **Vendor registry importers:** Microsoft, Salesforce, Databricks, AWS, Google and Snowflake.
