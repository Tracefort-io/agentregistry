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

- `type` is `"client"` instead of `"user"` when the token was issued to a client acting for itself (client credentials: `sub` equals the client ID, or the issuer's configured `clientSubjectClaim` says so).
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

## Deployments

A Deployment is authorized as its own resource (`type: deployment`) for `read`, `list` and `delete`. On `apply`, the registry additionally sends, in one batch with `deny_on_first_deny`:

- `deploy` on the target (`agent` or `mcpserver`, from `spec.targetRef`),
- `read` on the runtime (`runtime`, from `spec.runtimeRef`).

All must permit.

## Lists

1. `list` on the kind (`id` as above). A denial is `403`.
2. Rows the caller may `read` are selected:
   - if the PDP advertises Resource Search, with one `search/resource` call for `action: read`, `resource: {"type": "<kind>"}`;
   - otherwise with `evaluations` batches over the candidate rows, at most `AUTHZEN_LIST_MAX` rows. More candidates than that fails the request with `503`; enable Resource Search on the PDP for large catalogs.
3. The permitted `<namespace>/<name>` ids become a parameterized SQL condition on the list query, so rows the caller may not read are never returned.

## Responses

| Outcome | HTTP status |
|---|---|
| No token, or an invalid token | `401` with `WWW-Authenticate: Bearer` |
| PDP denies a `read` of one resource | `404` (existence is not disclosed) |
| PDP denies anything else | `403` |
| PDP unreachable, slow, or returns a malformed answer | `503` (still a denial) |

Every denial error matches `errors.Is(err, auth.ErrForbidden)`; an unauthenticated one matches `auth.ErrUnauthenticated`.

## Caching

Only permits are cached, per (subject, action, resource), for `AUTHZEN_CACHE_TTL` (default 5s). Denials and errors are never cached.
