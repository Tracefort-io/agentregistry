# Approval workflows for publish and deploy

A change can need someone else's approval before it takes effect, such as publishing an Agent or MCP server to the catalog, or deploying one. The registry holds such a change, an approver reviews it, and the registry applies it once it's approved. People use the web UI; agents and automation use the API.

The registry decides nothing about approvals itself. Every control is a Rego rule in the AuthZEN PDP, and the workflow runs in the PDP's access request service. Both follow the [OpenID AuthZEN Access Request and Approval Profile](https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html); [opa-authzen-plugin](https://github.com/tracefort-io/opa-authzen-plugin) implements it. The rules cover:

- which changes need approval;
- who approves them, and how many approvals are needed;
- how long an approval lasts;
- who may not approve, such as the requester.

## How it works

1. **Apply.** A user applies a change with `POST /v0/apply` (the UI does this too). For a change that needs approval, the PDP answers with a requestable denial: `decision: false`, plus `context.access_request` and a signed `binding_token`.
2. **Hold.** The registry submits an access request to the PDP for the user, with the registry's own credentials, and keeps the document. The apply returns `status: pending-approval` with `approvalRequest: arq_…`. Nothing is written.
3. **Review.** Approvers see the request in the UI's Approvals page (`GET /v0/approval-reviews`), with the document. They approve or deny it with an optional comment (`POST /v0/approval-reviews/{id}/decision`). The PDP checks each approver with its rules: an approver can't decide their own request.
4. **Apply.** The registry notices the approval, by polling every `APPROVALS_POLL_INTERVAL` or from the service's callback. It then applies the held document as the requester, presenting the approval. The PDP verifies it, and the request becomes `applied`.

An approval is bound to the subject, the action, the resource and the document's SHA-256 (`context.document_sha256`). The registry can apply only the document that was reviewed; any other content is refused as `out_of_scope`.

The requester follows the request under Approvals (`GET /v0/approvals`), and can withdraw it while it's pending (`POST /v0/approvals/{id}/cancel`).

| Request status | Meaning |
| --- | --- |
| `pending` | Waiting for an approver |
| `approved`, `applying` | Approved; the registry is applying it |
| `applied` | Applied. The detail says how, for example `created with approval apr_…`. |
| `denied` | An approver denied it |
| `expired` | Nobody decided before the request expired (the service's `task_ttl`) |
| `cancelled` | The requester withdrew it |
| `failed` | Approved, but applying failed. The detail says why, for example an approval that expired before it was applied. |

Dry runs are never held. Secrets are never held, because storing a pending Secret would put its values in the database. The single-resource `PUT` and `DELETE` routes don't hold changes; they answer `403 approval required`, so use `/v0/apply`.

## Policy

The reference rules are in [authzen/approvals.rego](auth/authzen/approvals.rego), with tests:

- a `registry-writer` publishing or deleting an Agent, MCPServer, Skill, Prompt or Plugin, or applying or deleting a Deployment, needs one approval;
- admins act directly;
- approvers are listed in `data.registry.approvers`;
- nobody approves their own change;
- only the registry's client may submit requests.

Change these rules to fit your organization: per namespace, per kind, two steps, a longer `approved_until`, and so on.

Configure the PDP (opa-authzen-plugin) with the access request service:

```yaml
plugins:
  authzen:
    decision_context: decision_context
    base_url: https://pdp.example.com
    capabilities: ["urn:openid:authzen:capability:access-request"]
    access_request:
      signing_key_file: /etc/authzen/pdp-signing.jwk     # an asymmetric private JWK with alg, e.g. ES256
      audience: https://pdp.example.com
      binding_context_members: ["document_sha256"]       # bind approvals to the reviewed document
      service:
        enabled: true
        database: {dsn_env: AUTHZEN_ARS_DSN}
        caller_auth:          # the registry's client-credentials tokens
          issuers: [{issuer: https://idp.example.com/realms/r, audience: https://pdp.example.com, jwks_uri: …}]
        approver_auth:        # approvers' tokens, forwarded by the registry
          issuers: [{issuer: https://idp.example.com/realms/r, audience: agentregistry, jwks_uri: …}]
        rules: {caller: ars_caller, workflow: ars_workflow, approver: ars_approver}
```

The registry forwards the approver's own token to the approver API, so `approver_auth` must accept the registry's audience (`agentregistry`).

## Registry settings

| Setting | Chart value | Default |
| --- | --- | --- |
| `AGENT_REGISTRY_APPROVALS_ENABLED` | `approvals.enabled` | `false` (needs `AUTH_MODE=required`) |
| `AGENT_REGISTRY_APPROVALS_TOKEN_URL`, `_CLIENT_ID`, `_CLIENT_SECRET(_FILE)`, `_SCOPES` | `approvals.tokenUrl`, `clientId`, `clientSecretRef`, `scopes` | The registry's OAuth client, accepted by `caller_auth` |
| `AGENT_REGISTRY_APPROVALS_POLL_INTERVAL` | `approvals.pollInterval` | `15s` |
| `AGENT_REGISTRY_APPROVALS_CALLBACK_URL`, `_CALLBACK_SECRET_FILE` | `approvals.callback.url`, `callback.secretRef` | Off. An https URL of `POST /approvals/callback`; the service only calls https. |

Every replica follows held requests. Each step moves a request on with a compare-and-set, so only one replica applies a given approval. A callback only tells the registry to check a request now: the registry reads the outcome from the service itself, and checks the callback's HMAC signature (`X-AuthZEN-Signature`) and timestamp.

## Audit

The registry records `request-approval` when it holds a change, and the apply it makes for an approved change, as the requester. The PDP records every step of the workflow (submitted, decided, approved, denied, expired, revoked) as OpenTelemetry log records.
