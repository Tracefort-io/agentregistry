# Agent identity assertion

How an agent workload proves who it is to agentgateway, and how the gateway
turns that proof into the registered agent and Deployment it belongs to.

This document covers identity assertion only: issuing identities, verifying
them, resolving them to registry records, and rejecting the ones that are
not valid. What an identified agent may do (authorization) and which
credentials it may use (credential brokerage) are separate steps that
consume the result described here.

Each part is marked:

- **Built**: implemented, merged and verified on the cluster.
- **Verified**: gateway behaviour confirmed on the cluster (agentgateway
  v1.7.0, 2026-11-24) with temporary test objects, since removed.
- **Designed**: specified here, not yet built.

## 1. The identity

**Built.** Every replica of an agent run by the registry's
KubernetesWorkload runtime gets its own SPIFFE ID:

```
spiffe://<trust domain>/org/<org>/agent/<agent>/deployment/<Deployment UID>/instance/<pod UID>
```

| Segment | Meaning |
|---|---|
| `org` | The registry namespace of the Deployment |
| `agent` | The registered Agent's name (must be a DNS label; never rewritten) |
| `deployment/<UID>` | The registry Deployment's UID |
| `instance/<UID>` | The Kubernetes pod's UID |

Both UIDs are generated and never reused, so a SPIFFE ID is never recycled:
an agent or Deployment re-created under the same name gets new IDs. The part
before `/instance/` is the Deployment's **identity prefix**, shared by its
replicas.

### Issuance

- SPIRE issues the identities. The org's ClusterSPIFFEID (created when the
  org is onboarded) builds the ID from two pod labels,
  `tracefort.io/agent` and `tracefort.io/deployment-uid`. Pods without both
  get no identity.
- Each pod receives an **X.509-SVID** (1 hour) and can fetch **JWT-SVIDs**
  (5 minutes, one audience each) from the SPIFFE Workload API socket
  mounted into the pod.
- ValidatingAdmissionPolicies in org namespaces let only the registry create
  or change workloads carrying the identity labels, forbid changing those
  labels on a pod, and refuse exec, attach, port-forward and debug
  containers, since each would act under an agent's identity.
- Agent pods have no Kubernetes API token and may reach only agentgateway
  and DNS.

### The registry's records

**Built.** The registry is the authority on which identity belongs to which
agent. Table `deployment_identity_events` (migration 020) is append-only:

| Event | When | Content |
|---|---|---|
| `assigned` | Before the workload is applied | Identity prefix, Deployment namespace/name/UID, Agent namespace/name/tag, Runtime, workload |
| `revoked` | When the Deployment is deleted or moved to another agent | The same details, copied from the assignment |

A prefix can be assigned once and revoked once, ever (partial unique
indexes). Undeploying keeps the identity; only deletion or a target change
revokes it. A Runtime still used by a Deployment that holds an identity
cannot be deleted, so no workload is left running with an identity the
registry no longer tracks.

## 2. The gateway's identity

**Built.** agentgateway's listener for agents, `https-agents`, serves TLS
with the gateway's own X.509-SVID
(`spiffe://<trust domain>/gateway/<namespace>/<gateway>`). Agent pods are
told that ID in `AGENTGATEWAY_SPIFFE_ID` and must check it before sending
anything, so an agent never sends its identity to anything but the gateway.

## 3. Asserting identity on each request

Every request an agent sends through `https-agents` passes four checks, in
this order, before routing:

```
agent ──mTLS (X.509-SVID)──▶ agentgateway listener https-agents
                               │ 1. TLS: client certificate required
                               │ 2. PreRouting jwtAuthentication: JWT-SVID
                               │ 3. PreRouting extAuth ──▶ registry identity check
                               │                            (binding, records)
                               │ 4. identity headers set from the registry's answer
                               ▼
                             routing, then authorization (not covered here)
```

### 3.1 Transport: the X.509-SVID

**Verified.** `https-agents` requires a client certificate: a connection
without one fails during the TLS handshake ("peer sent no certificates"). The
SPIFFE ID in the agent's X.509-SVID is then available to gateway policies as
`source.spiffeId`.

### 3.2 Token: the JWT-SVID

**Built as the listener policy `agent-identity`; deployed and verified.** The agent sends a JWT-SVID with
audience `agentgateway` in `Authorization: Bearer`. The gateway verifies:

- the signature, against keys from SPIRE's OIDC discovery provider (fetched
  over TLS that trusts the SPIFFE bundle, through the AgentgatewayBackend
  `spiffe-oidc`, path `/keys`);
- the issuer (SPIRE's OIDC discovery URL);
- the audience (`agentgateway`), so a token minted for another audience,
  such as OpenBao, is refused;
- expiry.

A request with no token or a token for another audience gets 401. After
validation the gateway removes the token, so it never reaches a backend.

### 3.3 The identity check

**Built, deployed and verified.** After the
JWT is verified, the gateway calls the registry's identity check (external
authorization in HTTP mode). The gateway builds the request itself, from
verified values only:

| Request header | Value | Source |
|---|---|---|
| `x-identity-token-subject` | The JWT-SVID's `sub` | `jwt.sub`, the verified token |
| `x-identity-certificate-id` | The certificate's SPIFFE ID | `source.spiffeId`, the verified TLS session |

The check is served at `/identity/check` on a listener of its own
(`IDENTITY_CHECK_ADDR`, chart `identityCheck`), which carries nothing else
and which only the gateway's pods may reach (NetworkPolicy).

Nothing the agent sends in its own headers is used. The registry then:

1. **Binds the two proofs.** The JWT `sub` and the certificate ID must be the
   same SPIFFE ID; otherwise the request is rejected. This stops a JWT-SVID
   from being replayed over a connection that holds another workload's
   certificate. (Verified: the gateway does not compare them itself; a
   mismatched pair reaches the check, so the check must refuse it.)
2. **Parses the ID.** Exactly the form in section 1, in the configured trust
   domain; org and agent are DNS labels, both UIDs are UUIDs. Anything else
   is rejected.
3. **Looks up the identity prefix** in `deployment_identity_events`. The ID
   resolves only if the prefix has an `assigned` record and no `revoked`
   record, and the record's org (Deployment namespace), agent and Deployment
   UID equal the ID's segments.
4. **Answers.** On success, HTTP 200 with the resolved identity:

   | Response header | Value |
   |---|---|
   | `x-agentregistry-agent` | `<namespace>/<name>:<tag>` |
   | `x-agentregistry-deployment` | `<namespace>/<name>` |
   | `x-agentregistry-deployment-uid` | Deployment UID |
   | `x-agentregistry-spiffe-id` | The verified SPIFFE ID |

   Otherwise HTTP 403 with no detail; the reason is logged without any token.

The check is not cached: every request is checked against the current
records.

### 3.4 Passing the resolved identity on

**Verified.** The gateway copies the check's response headers onto the
request. A header of the same name sent by the agent is replaced, not kept
alongside: in the test, an agent-forged `x-agentregistry-agent` never reached
the upstream, only the check's value did. So an agent's own claim about who
it is can never override its verified identity.

### 3.5 Why PreRouting

**Verified from the agentgateway docs** (policy processing order;
`AgentgatewayPolicy.spec.traffic.phase`). The JWT verification and the
identity check run in the **PreRouting** phase of a policy attached to the
`https-agents` listener:

- PreRouting runs before any route is chosen, in a fixed order: JWT
  authentication, then external authorization.
- PreRouting policies can attach only to a Gateway or listener, and PreRouting
  and PostRouting rules never merge. A route's own policy therefore cannot
  replace or weaken the identity check. (In PostRouting, a route policy that
  sets `extAuth` would replace a listener's.)
- External authorization fails closed by default: if the check answers
  anything but 200, or cannot be reached, the request is rejected (verified
  with a 403 from the stand-in).

## 4. Rejections

| Case | Rejected by | Result |
|---|---|---|
| No client certificate | Gateway TLS | Connection refused |
| No JWT-SVID, bad signature, wrong issuer or audience, expired | Gateway JWT authentication | 401 |
| Certificate ID and JWT `sub` differ | Identity check | 403 |
| ID not in the expected form or trust domain | Identity check | 403 |
| Prefix never assigned (unknown) | Identity check | 403 |
| Prefix revoked | Identity check | 403 |
| Org, agent or Deployment UID in the ID disagree with the record | Identity check | 403 |
| Identity check unreachable | Gateway (fail closed) | Rejected |

## 5. Revocation

Four independent controls stop an identity:

- **Registry record.** Deleting a Deployment records `revoked` for its prefix.
  The identity check rejects the prefix on the next request, even while an
  SVID issued earlier has not expired (JWT-SVID up to 5 minutes, X.509-SVID
  up to 1 hour).
- **Issuance.** When the workload is removed, its pods are gone, so SPIRE
  issues no new SVIDs for them; pod UIDs are never reused.
- **Network.** The agent's NetworkPolicy allows only the gateway and DNS.
- **Admission.** Only the registry can create pods carrying identity labels.

## 6. What an agent does

1. Connect to `AGENTGATEWAY_URL` over TLS, presenting its X.509-SVID, and
   check that the gateway's certificate carries `AGENTGATEWAY_SPIFFE_ID`.
2. Fetch a JWT-SVID with audience `AGENTGATEWAY_AUDIENCE` (default
   `agentgateway`) from the Workload API at `SPIFFE_ENDPOINT_SOCKET`, and send
   it as `Authorization: Bearer` on every request. Fetch a new one before it
   expires (5 minutes).
3. Never send `x-agentregistry-*` headers; they are replaced anyway.

## 7. Status

| Part | Status |
|---|---|
| Per-replica SPIFFE IDs, issuance, admission guards | Built |
| Identity records (assigned / revoked) | Built |
| Gateway X.509-SVID on `https-agents`; agents told its ID | Built |
| mTLS required on `https-agents`; `source.spiffeId` available | Verified |
| PreRouting JWT-SVID verification (SPIRE keys via `spiffe-oidc`, audience, token removal) | Built, deployed, verified |
| PreRouting extAuth: verified `jwt.sub` sent; response headers replace forged ones; fail closed | Verified with a stand-in check |
| Registry identity check (binding, parser, record lookup, internal listener; `internal/registry/workloadidentity`) | Built, deployed, verified |
| `AGENTGATEWAY_AUDIENCE` on agent pods (Runtime `spec.config.gateway.audience`) | Built, deployed |
| Listener policy `agent-identity` and backend `spiffe-oidc` (control-plane-prod) | Built, deployed, verified |
| NetworkPolicy: only gateway pods reach the identity check | Built, deployed |

### Verification on the cluster (2026-11-24, agentgateway v1.7.0)

With a Deployment registered through the registry (Agent
`identity-check-probe` 1.0.0) and SVIDs minted for its pod's SPIFFE ID:

| Test | Result |
|---|---|
| The pod's ID, certificate and JWT | 200; upstream received the resolved Agent, Deployment, UID and SPIFFE ID, and no `Authorization` |
| The same, plus a forged `X-Agentregistry-Agent` | 200; only the registry's value reached the upstream |
| Certificate for the pod, JWT for another instance | 403 ("JWT-SVID and X.509-SVID name different SPIFFE IDs") |
| Unknown Deployment UID | 403 ("identity was never assigned") |
| The pod's ID after the Deployment was deleted | 403 ("identity was revoked"), although SPIRE could still mint SVIDs for it |

## 8. Not covered here

- **Authorization**: what a resolved agent may do is decided afterwards, by
  policy, using the resolved identity.
- **Credential brokerage**: fetching upstream credentials as the agent from
  OpenBao.
- **Keycloak** logical agent identities and human delegation.

## References

- `internal/registry/runtimes/kubernetes/`: the runtime that labels pods and
  records identity prefixes.
- `internal/registry/controller/identity.go`: assignment and revocation.
- `pkg/registry/v1alpha1store/identity_events.go`: the identity records
  (`IdentityHistory`, `RevokedIdentities`).
- `internal/registry/workloadidentity/`: the ID parser, the resolver and the
  check handler.
- control-plane-prod `deployment/manifests/agentgateway/agent-identity.yaml`
  and `spiffe.yaml`: the listener policy and the keys' backend.
- [agent-identity.md](agent-identity.md): the overall agent identity and
  credential brokerage design.
- control-plane-prod `deployment/20-spire.sh`, `deployment/21-org.sh`: SPIRE,
  the gateway's SVID, org onboarding (ClusterSPIFFEID, admission policies).
