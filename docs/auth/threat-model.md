# Threat model: authentication and authorization

Scope: the registry API, web UI and MCP endpoint with `AGENT_REGISTRY_AUTH_MODE=required`. See [authzen-contract.md](authzen-contract.md) for what is sent to the PDP and [authz-matrix.md](authz-matrix.md) for each endpoint.

## What is protected

- Catalog entries (agents, MCP servers, skills, prompts, plugins, models) and who may publish or change them.
- Runtimes, Deployments and Secrets: they decide what runs where, and with which credentials.
- The ability to deploy: a Deployment runs the target with the Runtime's and the Model's credentials.

## Trust boundaries

| Boundary | Who is trusted for what |
| --- | --- |
| Identity provider (Keycloak, Entra ID, any OIDC issuer) | Issues tokens. The registry trusts only the issuers in `AUTH_ISSUERS`, and only tokens for its audience. |
| AuthZEN PDP | Decides every operation. The registry trusts its answers, fetched over the configured URL with its own credentials. |
| Gateway in front of the registry (optional) | May check tokens and policy first. The registry does not rely on it: it authenticates and authorizes every request itself. |
| Browser | Holds the user's tokens in memory only. Not trusted to decide anything. |

## Threats and mitigations

| Threat | Mitigation | Where |
| --- | --- | --- |
| Calling the API without a token, or around the gateway | Every request except `AUTH_OPEN_PATHS` and the UI's static files needs a valid token, checked by the registry itself. Open paths match exactly, so a resource named `health` is not open. | `pkg/registry/auth`, `internal/registry/api/router` |
| Forged or altered tokens | Signature checked against the issuer's published keys; `none` and HMAC algorithms refused; issuer, audience, expiry and not-before checked, with bounded clock skew. | `pkg/registry/auth/jwt` |
| A token for another service | The audience must be one configured for the registry. | `pkg/registry/auth/jwt` |
| Doing more than the role allows | Every operation is asked of the PDP; a denial is `403`, or `404` for a read so existence is not disclosed. | `internal/registry/authz` |
| Deploying with someone else's resources | Applying a Deployment also needs `read` on its Runtime, Model and bound Deployments, and `deploy` on its target. | `internal/registry/authz/deployment.go` |
| Seeing rows through a list | Lists return only rows the caller may read, filtered in SQL with bound parameters. | `internal/registry/authz/listfilter.go` |
| PDP down or slow | Every PDP call is time-bounded; any failure is a denial (`503`). Only permits are cached, briefly, so a revoked permission takes effect within `AUTHZEN_CACHE_TTL`. | `pkg/registry/authzen` |
| Starting without protection | With `AUTH_MODE=required` the server refuses to start unless issuers (or an `AuthnProvider`) and a PDP are configured. | `internal/registry/config`, `internal/registry/auth_wiring.go` |
| Token theft from the browser | Tokens stay in memory, never in `localStorage` or `sessionStorage`; sign-in uses the authorization code flow with PKCE; the return path after sign-in must stay on the site. | `ui/lib/auth.tsx` |
| Changing log levels remotely | `/logging` is localhost-only and, with auth required, also needs a token. | `internal/registry/api/router` |
| Tracing a decision | Every request carries an `X-Request-ID`, sent to the PDP, so registry logs and decision logs can be joined. | `internal/registry/api/router` |

## Residual risks

- **The PDP's policy is the control.** A permissive policy permits; review it like code. The reference policy is [authzen/registry.rego](authzen/registry.rego).
- **Revocation lag.** A permission revoked in the PDP can still be honored for up to `AUTHZEN_CACHE_TTL` (default 5s); a revoked token until it expires.
- **`/v0/me` is advisory.** It reports permissions on whole collections; a policy that decides per resource can still deny an individual request.
- **Batch apply reports denials per document** with HTTP `200`; clients must read each result's `status`.
- **Internal system sessions** (controllers, reconciliation) skip the PDP by design.
- **Static PDP tokens** (`AUTHZEN_STATIC_TOKEN`) are shared secrets; prefer OAuth client credentials.
- **No audit log yet.** Decisions are logged, but there is no tamper-evident record of who changed what.
