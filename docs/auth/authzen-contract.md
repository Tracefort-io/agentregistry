# AuthZEN contract

With `AGENT_REGISTRY_AUTH_MODE=required`, the registry authenticates every request itself and asks an [OpenID AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) Policy Decision Point (PDP) before every operation. This document fixes the requests the registry sends, so that policies can be written for any compliant PDP. The reference policy for OPA is in [authzen/registry.rego](authzen/registry.rego).

The registry uses only the AuthZEN 1.0 core:

- `GET /.well-known/authzen-configuration` to discover endpoints,
- `POST /access/v1/evaluation` for one decision,
- `POST /access/v1/evaluations` for a batch,
- `POST /access/v1/search/resource`, only when the PDP advertises it.

## Subject

Built only from verified token claims.

```json
{
  "type": "user",
  "id": "<sub>",
  "properties": {
    "iss": "<iss>",
    "username": "<preferred_username or upn>",
    "client_id": "<azp or client_id>",
    "roles": ["..."],
    "groups": ["..."],
    "act": [{"sub": "...", "iss": "..."}]
  }
}
```

- `type` is `"client"` instead of `"user"` when the token was issued to a client acting for itself. The issuer's `clientSubjectClaim` decides when it is configured; otherwise a token whose `sub` equals its client ID is a client token.
- `roles` and `groups` come from the claim paths configured per issuer (Keycloak `realm_access.roles` and `groups`; Entra `roles` and `groups`).
- `act` is present only for delegated tokens (RFC 8693).
- Anonymous callers on public paths are sent as `{"type": "anonymous", "id": "anonymous"}`.

## Action

| Registry operation | `action.name` |
|---|---|
| Get one resource or tag | `read` |
| List a kind | `list` |
| Create or replace (`apply`) | `apply` |
| Delete | `delete` |
| Create or change a Deployment | `deploy` (on the target) |
| Registry-wide admin check | `admin` |

## Resource

```json
{
  "type": "<kind in lower case>",
  "id": "<namespace>/<name>",
  "properties": {"kind": "<Kind>", "namespace": "...", "name": "...", "tag": "..."}
}
```

- `type` is one of `agent`, `mcpserver`, `skill`, `prompt`, `plugin`, `model`, `runtime`, `deployment`, `secret`. Extension kinds use their lower-cased Kind.
- `tag` is present for tagged kinds when the operation names a tag.
- For `list`, `id` is `<namespace>/*`, or `*` across all namespaces.
- The admin check uses `{"type": "registry", "id": "agentregistry"}`.

## Context

```json
{"request_id": "<X-Request-ID>", "pep": "agentregistry"}
```

An `apply` (and every check of a Deployment apply) also carries `document_sha256`, the SHA-256 of the submitted document's JSON. It's never sent for Secrets. A policy that binds it (`binding_context_members: ["document_sha256"]`) ties an approval to exactly the reviewed content.

When the registry applies an approved change, the context also carries `"approval": {"id": "apr_…"}`. The PDP replaces it with its verification (`verified`, or `reason: approval_expired | out_of_scope | approval_unverifiable`) before the policy runs. See [approvals](../approvals.md).

## Deployments

A Deployment is authorized as its own resource (`type: deployment`) for `read`, `list` and `delete`. On `apply`, the registry sends one batch with `deny_on_first_deny`:

- `deploy` on the target (`agent` or `mcpserver`, from `spec.targetRef`),
- `read` on the runtime (`runtime`, from `spec.runtimeRef`),
- `apply` on the Deployment itself,
- `read` on the Model it uses (`model`, from `spec.modelRef`, or the namespace's `default` Model for a harness Agent that names none),
- `read` on each Deployment it binds to (`deployment`, from `spec.deploymentRefs`).

All must permit, so a Deployment cannot run with, or bind to, a resource its author may not read. A reference without a namespace is in the Deployment's namespace.

## Lists

1. `list` on the kind (`id` as above). A denial is `403`.
2. Rows the caller may `read` are selected:
   - if the PDP advertises Resource Search, with `search/resource` calls for `action: read`, `resource: {"type": "<kind>"}`, following every page;
   - otherwise with `evaluations` batches of 100 over the candidate rows, up to 4 batches at a time.

   Either way at most `AUTHZEN_LIST_MAX` results or candidates are authorized. More than that fails the request with `503`.
3. The permitted rows become a parameterized SQL condition on the list query, so rows the caller may not read are never returned.

Resource Search results may name more than one row, for policies that decide by role rather than by row:

| Result `id` | Means | Becomes |
| --- | --- | --- |
| `<namespace>/<name>` | That row (every tag of it) | `(namespace, name)` match |
| `<namespace>/*` | Every row of the kind in the namespace | `namespace` match |
| `*` | Every row of the kind | No filter |

Results of another type are ignored, and so are namespaces outside a namespace-scoped list. Such a policy answers in a single result, so large catalogs list without per-row checks; [authzen/registry.rego](authzen/registry.rego) has a `search_resource` rule that does this.

## Permissions (`GET /v0/me`)

`GET /v0/me?namespace=<ns>` tells a client such as the web UI who the caller is and which actions they may take, so it can show only the actions that will succeed. The registry sends one `evaluations` batch with `execute_all` (split into batches of 100 if needed):

- `admin` on `{"type": "registry", "id": "agentregistry"}`,
- for each kind, `read`, `list`, `apply` and `delete` (and `deploy` for `agent` and `mcpserver`) on the kind's collection: `id` `<namespace>/*`, or `*` for `namespace=all`.

```json
{
  "authenticated": true, "subject": "<sub>", "issuer": "<iss>", "username": "bob",
  "roles": ["registry-reader"], "namespace": "default", "enforced": true, "admin": false,
  "permissions": {"Agent": ["read", "list"], "Secret": []}
}
```

The answer is advisory: every request is still authorized on its own, and a policy that decides per resource may deny an action the collection check allowed. Without authorization the registry reports every action as allowed with `enforced: false`.

## Responses

| Outcome | HTTP status |
|---|---|
| No token, or an invalid token | `401` with `WWW-Authenticate: Bearer` |
| PDP denies a `read` of one resource | `404` (existence is not disclosed) |
| PDP denies anything else | `403` |
| PDP denies an `apply` or `delete` as requestable (`context.access_request` with a `binding_token`) | In `/v0/apply`, with approvals enabled: held, per-document `status: pending-approval` and `approvalRequest`. Otherwise `403`. |
| PDP unreachable, slow, or returns a malformed answer | `503` (still a denial) |

Every denial error matches `errors.Is(err, auth.ErrForbidden)`; an unauthenticated one matches `auth.ErrUnauthenticated`.

## Caching

Only permits are cached across requests, per (subject, action, resource), for `AUTHZEN_CACHE_TTL` (default 5s). Denials and errors are never cached.

Within one incoming request, an identical question is asked once: a decision, permit or denial, is reused for the rest of that request only. Failed evaluations are not reused.
