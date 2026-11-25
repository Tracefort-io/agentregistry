# MCP servers through agentgateway

With `gatewayConfig.enabled` (env `GATEWAY_CONFIG_ENABLED`), the registry writes
agentgateway's configuration for every live tag of every MCPServer that has
`spec.remote`. Agents reach the server only through the gateway's listener for
agents, and never hold its credential.

This builds on [agent identity assertion](agent-identity-assertion.md): before
any route is chosen, the listener has verified the agent's X.509-SVID and
JWT-SVID and resolved them, through the registry's identity check, to the
registered Agent and Deployment. That identity arrives as headers the gateway
set itself (`x-agentregistry-*`), replacing any the agent sent.

## What the registry writes

In the gateway's namespace, for MCPServer `<namespace>/<name>` tag `<tag>`
(objects named `mcp-<name>-<digest>`, labelled
`app.kubernetes.io/managed-by=agentregistry`,
`app.kubernetes.io/component=mcp-gateway`):

| Object | Content |
|---|---|
| AgentgatewayBackend | One static MCP target from `spec.remote.url` (`streamable-http` or `sse`; TLS when the URL is https). `spec.remote.headers` is refused: use `spec.credential`. |
| HTTPRoute | `/mcp/<namespace>/<name>/<tag>` on the Gateway's listener for agents. |
| AgentgatewayPolicy | The guardrail callout for every MCP message (`tools/list` also on the response, to filter it), failing closed. The callout receives only the resolved identity headers and the agent's SVID for OpenBao. No authentication of its own: the listener's identity policy already did it, and a route policy cannot replace that. |

A deleted tag loses its objects; objects the registry no longer wants are
removed. The registry syncs on every repair pass of the elected replica
(each minute) and right after an MCPServer is applied or deleted. A server it
cannot route (an unsupported URL or transport, or a credential without
OpenBao org namespaces) gets no route, and the registry logs why.

## Authorization

agentgateway is the PEP; OPA is the PDP and decides every MCP message. The
guardrail callout (extauth-bridge) is agentgateway's AuthZEN client: it turns
each message into an AuthZEN request, asks the PDP and returns the answer for
agentgateway to enforce. It decides nothing itself.

Each request is built from the identity agentgateway verified and resolved,
passed in the processor's metadata:

- `subject.id`: the agent's SPIFFE ID, the verified token's `sub`, which must
  equal the SPIFFE ID the identity check resolved;
- `context.agent`: the resolved Agent, `<namespace>/<name>:<tag>`, as the
  COAZ-MCP binding requires for autonomous agents;
- `context.mcp_server`: the server version, from the route's configuration;
- `action` and `resource`: the binding's mapping for the method (and a
  tool's declared mapping for `tools/call`). A method the binding gives no
  mapping, such as `initialize`, `server/discover`, `ping` and
  notifications, is sent as action = the method, resource = the MCP server,
  so the PDP decides it too.

A message without a resolved identity, or whose request cannot be built
(malformed parameters, a tool not yet listed through the gateway), is
refused without asking the PDP.

agentgateway runs `resources/subscribe`, `resources/unsubscribe` and
`completion/complete` only through the response phase of its guardrails.
For these three the decision is made on the response, with the server-level
request (the response hook carries no request parameters): a denied
response is withheld, but the upstream server has already received the
request, without a credential.

## The contract for agents

On top of the identity assertion contract (X.509-SVID for mTLS, JWT-SVID with
audience `AGENTGATEWAY_AUDIENCE` in `Authorization`), an agent calling a server
with a credential also sends:

| Header | JWT-SVID audience | Who reads it |
|---|---|---|
| `AGENTGATEWAY_OPENBAO_SVID_HEADER` (default `x-openbao-svid`) | `OPENBAO_AUDIENCE` (default `openbao`) | Only the guardrail callout, which removes it from every upstream request, for every server, so no server can log in to OpenBao as the agent. |

The KubernetesWorkload runtime sets these environment variables on agent pods
(Runtime `spec.config.gateway.openBaoAudience`, `openBaoSVIDHeader`); they
must match the registry's `gatewayConfig` and OpenBao settings.

Any other route added to the listener for agents must remove the SVID header
itself: it cannot be removed at the listener, since the callout needs it
later in the request.

## Credentials

For a server with `spec.credential`, the callout's metadata names the
credential: the org's OpenBao namespace, the grant's role
(`mcp-<server>-<digest>`, written by the credential grants for the agents
whose Agent lists the server), the KV path, the key, the header and the
scheme, and always the SVID header. After the PDP allows the call, the
callout checks that the SVID for OpenBao names the resolved SPIFFE ID, logs
in to OpenBao with it and reads the credential; OpenBao decides on its own
whether that identity may have it. The callout then has the gateway set the
header on the upstream request. Any failure denies the call.

The gateway cannot perform the two OpenBao calls itself in this order (its
external authorization runs before MCP guardrails, has no request method
setting and cannot chain calls), so the callout makes them; it holds the
credential only for the request.

## Verification

On k3s (agentgateway v1.7.0), 2026-11-25, with a test MCP server that reports
a fingerprint of the credential it receives (tracefort-ext-services
`testing/mcp-echo`), registered as MCPServer `default/echo-mcp` 1.0.0 with a
credential, and an agent `default/echo-probe` 1.0.0 listing it, called with
SVIDs for the agent pod's SPIFFE ID:

| Case | Result |
|---|---|
| No rule allows the agent | `initialize` sent to OPA (subject: the pod's SPIFFE ID; `context.agent`: `default/echo-probe:1.0.0`; resource: the server) and denied; no OpenBao login; nothing reached the server |
| A rule allows `initialize`, `notifications/initialized`, `tools/list` and the tool `whoami` | Each allowed by OPA, then the credential fetched from OpenBao as the agent (org `org-default`, the grant's role) and injected |
| `tools/call whoami` | The server received the credential (fingerprint equal to the stored value's), the resolved identity headers, and no SVID for OpenBao |
| The same call without the SVID for OpenBao | Allowed by OPA, then refused: "credential unavailable" |
| Deleting the Deployment and the MCPServer | The route, backend and policy were removed and the agent's identity revoked |

## Known limits

- **Bundled MCP servers get no route.** Only MCPServers with `spec.remote` are
  routed. A server that runs from an image (for example from Harbor) and is
  deployed by the registry is not reachable through the listener for agents
  yet.
- **Remote server URLs are not checked for provenance.** Any URL with a host
  is accepted for `spec.remote`, and the gateway sends the server's
  credential there. Publishing by a registry-writer needs an approval, the
  credential must be in the server's namespace, and OPA decides every call,
  but nothing verifies who runs the endpoint.
- **Three methods are decided after the upstream call.** agentgateway runs
  `resources/subscribe`, `resources/unsubscribe` and `completion/complete`
  only through the response phase of its guardrails: the server receives the
  request, without a credential, before the PDP decides, and a denied
  response is withheld.
- **The SVID header on other routes.** Only the guardrail callout removes
  `x-openbao-svid`; any other route on the listener for agents must remove it
  itself (see above).
