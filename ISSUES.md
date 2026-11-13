# Pending issues

Open work and known problems in this repository. Remove an entry when it's fixed, and say in the commit which one it closes. Last updated 2026-11-12.

## In progress

### 1. Approval workflows for publish and deploy: not deployed or tested through agentgateway

The code is on the `approvals` branch, uncommitted, and has been tested only locally, against opa-authzen-plugin built from main, without agentgateway or Keycloak. See [docs/approvals.md](docs/approvals.md). To verify it on k3s:

- **PDP:** opa-authzen-plugin's access request service isn't released yet (it's on main after `v0.10.0`), so it needs an image built from main. It also needs its configuration (database, signing key, caller and approver auth, `binding_context_members: ["document_sha256"]`) and the approval rules from [approvals.rego](docs/auth/authzen/approvals.rego) merged into the deployed policy.
- **Gateway:** agentgateway's coarse rule allows writes under `/v0/` only to writers and admins, so an approver without one of those roles is refused at `POST /v0/approval-reviews/{id}/decision`.
- **Keycloak:** a confidential client for the registry (client credentials, with the PDP as audience), and an approver user listed in the policy's `data.registry.approvers`.
- **Callbacks:** the PDP only calls `https` URLs, so a registry served over plain HTTP learns outcomes by polling (`APPROVALS_POLL_INTERVAL`).

Known flaws:

- **Duplicated status:** the registry's `approval_requests` table keeps a copy of each request's status, which the access request service already tracks. The registry needs only the held document and the requester.
- **A decision in code, not Rego:** who may see or withdraw a held change under `/v0/approvals` (the requester or an admin) is decided in the registry's code, not by OPA (`ars_caller`).

Not built yet:

- **Stale detection:** a live resource that changed between request and approval isn't detected; the reviewed document is applied over it.
- **No diff in the review:** the review page shows the submitted document, not a diff against the live resource.
- **Single-resource routes:** `PUT` and `DELETE` on a single resource don't hold changes; they answer `403 approval required`.
- **Static approvers:** approvers are a static list in policy data.
- **Notifications:** none, for example to Slack or Teams.

## Bugs

### 2. A startup failure can hang without logging its error, and SIGTERM may not stop the process

When `registry.App` returns an error, or shuts down after SIGTERM, closing the database pool can wait forever for connections that background goroutines still hold: controllers, LISTEN subscriptions, loops on `context.Background()`. The error is never logged, and the pod stalls until its probe kills it.

It was seen twice: when a schema-name clash crashed route registration, and when a local registry ignored SIGTERM. A fix needs an app-scoped context, canceled before the pool closes, and the error logged before shutdown.

### 3. Tags aren't validated on apply

`metadata.tag: Bad Tag!` is accepted on `POST /v0/apply`, although the tag rule (`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`) forbids it. Names are validated; tags aren't.

## Gaps

### 4. Writes refused at the gateway aren't in the registry's audit log

agentgateway refuses some writes (for example, a reader's apply) before they reach the registry, so the registry can't record them. Only the gateway's logs have them.

### 5. Leader election

- **Lease expiry untested live:** a crashed Kubernetes Lease holder, where standbys wait out the 15s lease, wasn't tested on a cluster. Force-deleting a pod still sends SIGTERM, so the Lease was released, not expired.
- **No guard against mixed mechanisms:** replicas on `postgres` and `kubernetes` don't see each other, and changing the mechanism on a running system relies on stopping the old pods first.
- **No leader metric:** there's no `agentregistry_leader` metric yet; only logs show who leads.

### 6. Secrets

- **Database store:** it still encrypts with one static AES key, with no rotation. OpenBao option B, a Transit envelope with re-wrapping, isn't built.
- **OpenBao setup by hand:** for the OpenBao store, the setup (KV mount, policy, Kubernetes role) is done by hand from [docs/secrets-openbao.md](docs/secrets-openbao.md).

### 7. HTTP hardening

The web UI's Content-Security-Policy allows `'unsafe-inline'` scripts, because Next.js inlines its bootstrap code. Nonces or hashes would remove that.

### 8. Identity

Only Keycloak has been tested; Entra ID hasn't. [test/authe2e](test/authe2e/README.md) shows how to run the per-role test with Entra tokens.

## Code health

### 9. Lint and type errors in older code

- **Integration-tagged tests:** `golangci-lint` with `--build-tags=integration` reports findings in older tests (`sort` imports, loops that could range over int, testify assertions), for example `store_tagging_test.go`, `store_test.go`, `adapter_resolver_test.go` and `predicate_integration_test.go`.
- **UI type check:** `npx tsc --noEmit` fails in `ui/components/__tests__/server-card.test.tsx` (`repository` isn't on `McpServerSource`).
- **UI lint:** ESLint warns about a missing `fetchData` dependency in `ui/app/page.tsx`.

### 10. Tooling

- **Go version:** with Go 1.27 installed, the pinned golangci-lint can't read the standard library. Run `GOTOOLCHAIN=go1.26.9 make lint`.
- **Network-dependent test:** `TestValidateNPM_RealPackages` calls the real npm registry and fails when DNS or the network is unavailable.

## Roadmap

### 11. Features not started

- **Runtimes:** AgentCore and Virtual.
- **Gateway binding:** publish a deployed agent or MCP server through agentgateway.
- **Vendor registry importers:** Microsoft, Salesforce, Databricks, AWS, Google and Snowflake.
