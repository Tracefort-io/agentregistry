# Keeping Secret values in OpenBao

With `secretStore.type: OpenBao` (`AGENT_REGISTRY_SECRET_STORE=OpenBao`), the registry keeps a Secret's metadata and key names in Postgres and its values in an OpenBao KV version 2 engine. Values never reach Postgres or Kubernetes Secrets. OpenBao's policies decide who may read them, and its audit device records every access.

Each Secret `<namespace>/<name>` is stored at `<mount>/data/<pathPrefix>/<namespace>/<name>`, by default `agentregistry/data/secrets/<namespace>/<name>`. Each key's value is stored base64-encoded, as in Kubernetes Secrets, so any bytes round-trip. An update writes a new version; a delete destroys every version.

## 1. Set up OpenBao

Run these as an OpenBao administrator (for example `kubectl exec -it openbao-0 -- sh` with `BAO_TOKEN` set to a root or admin token).

```shell
# A KV v2 engine for the registry.
bao secrets enable -path=agentregistry -version=2 kv

# The registry may write, read and delete under its prefix, and nothing else.
bao policy write agentregistry - <<'EOF'
path "agentregistry/data/secrets/*"     { capabilities = ["create", "update", "read"] }
path "agentregistry/metadata/secrets/*" { capabilities = ["delete"] }
EOF
```

Then let the registry log in, with one of these methods.

**Kubernetes (recommended in a cluster).** The registry presents its service account token; OpenBao checks it with the Kubernetes API. OpenBao's Helm chart grants it the `system:auth-delegator` role this needs.

```shell
bao auth enable kubernetes
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
bao write auth/kubernetes/role/agentregistry \
    bound_service_account_names=agentregistry \
    bound_service_account_namespaces=<registry namespace> \
    token_policies=agentregistry token_ttl=1h token_max_ttl=24h
```

**AppRole (outside Kubernetes).**

```shell
bao auth enable approle
bao write auth/approle/role/agentregistry token_policies=agentregistry token_ttl=1h secret_id_ttl=0
bao read -field=role_id auth/approle/role/agentregistry/role-id
bao write -f -field=secret_id auth/approle/role/agentregistry/secret-id
```

Store both values in a Kubernetes Secret (keys `role-id` and `secret-id`) and name it in `secretStore.openbao.appRoleSecretRef.name`.

**Token (development only).** A token with the `agentregistry` policy in a Kubernetes Secret, named in `secretStore.openbao.tokenSecretRef.name`. The registry does not renew it beyond what OpenBao allows.

## 2. Configure the registry

```yaml
secretStore:
  type: OpenBao
  openbao:
    address: https://openbao.<namespace>.svc:8200
    auth: kubernetes
    role: agentregistry
    # mount: agentregistry
    # pathPrefix: secrets
    # The CA that signed OpenBao's certificate, when it isn't publicly trusted:
    # a ConfigMap (a CA certificate is public) or a Secret, not both.
    # caConfigMapRef: {name: internal-ca, key: ca.crt}
    # caSecretRef: {name: openbao-ca, key: ca.crt}
```

| Setting | Chart value | Default |
| --- | --- | --- |
| `AGENT_REGISTRY_OPENBAO_ADDR` | `secretStore.openbao.address` | required |
| `AGENT_REGISTRY_OPENBAO_NAMESPACE` | `secretStore.openbao.namespace` | root namespace |
| `AGENT_REGISTRY_OPENBAO_MOUNT` | `secretStore.openbao.mount` | `agentregistry` |
| `AGENT_REGISTRY_OPENBAO_PATH_PREFIX` | `secretStore.openbao.pathPrefix` | `secrets` |
| `AGENT_REGISTRY_OPENBAO_AUTH` | `secretStore.openbao.auth` | `kubernetes` |
| `AGENT_REGISTRY_OPENBAO_AUTH_MOUNT` | `secretStore.openbao.authMount` | the method's default path |
| `AGENT_REGISTRY_OPENBAO_ROLE` | `secretStore.openbao.role` | `agentregistry` |
| `AGENT_REGISTRY_OPENBAO_APPROLE_ROLE_ID_FILE`, `_SECRET_ID_FILE` | from `appRoleSecretRef` | |
| `AGENT_REGISTRY_OPENBAO_TOKEN_FILE` | from `tokenSecretRef` | |
| `AGENT_REGISTRY_OPENBAO_CA_CERT_FILE` | from `caConfigMapRef` or `caSecretRef` | system roots |
| `AGENT_REGISTRY_OPENBAO_TIMEOUT` | `secretStore.openbao.timeout` | `10s` |

At startup the registry logs in and reads a path that does not exist, and logs `OpenBao secret store ready`, or a warning with the cause. It starts either way, since OpenBao may come up later. Until OpenBao is reachable, applying or deleting a Secret, and anything that resolves a Secret's value, fails with an error naming OpenBao; the rest of the registry works.

The registry renews its token before it expires and logs in again when OpenBao refuses it, re-reading the credential files, so rotated service account tokens and secret IDs are picked up.

## 3. Move existing values

Set `secretStore.migrateFrom` to the store you used before (`Kubernetes` or `Database`), keeping that store's settings in place:

```yaml
secretStore:
  type: OpenBao
  migrateFrom: Kubernetes
```

At startup the registry copies every Secret's payload that OpenBao does not have yet, reads each copy back to verify it, and logs a summary (`copied`, `already_present`, `missing_in_source`, `failed`). It never overwrites a value already in OpenBao and never deletes the originals. Failed copies, for example while OpenBao is not reachable yet, are retried after 5 seconds, then at doubling intervals up to 5 minutes, until a pass has none. Once the summary shows no failures, remove `migrateFrom` and delete the old copies: the Kubernetes Secrets labelled `agentregistry.solo.io/managed-by=secret-store`, or the `secret_payloads` table's rows.

## 4. Check it

```shell
# A value applied through the registry is in OpenBao...
bao kv get -mount=agentregistry secrets/<namespace>/<name>
# ...and in neither Postgres nor Kubernetes Secrets.
```

To record every read and write, enable an OpenBao audit device (`bao audit enable file file_path=stdout`).

## 5. One OpenBao namespace per organization

With `secretStore.openbao.orgNamespacePrefix` (for example `org-`), the Secrets of each registry namespace live in their own OpenBao namespace, `<prefix><namespace>`, a child of `secretStore.openbao.namespace`, at `<mount>/data/<pathPrefix>/<name>`. Each organization's values are confined to its namespace: a policy written inside one cannot reach another namespace or the parent's mounts. The registry logs in in the parent namespace and needs, in each org namespace, the KV mount and a policy over it.

To move existing values from the single-namespace layout, set `migrateFrom: OpenBao` together with `orgNamespacePrefix`. The registry copies each payload into its org namespace and verifies it, as in step 3; it never deletes the originals, so remove them once the summary shows no failures.

### Credentials of MCP servers

An MCP server can name the credential the gateway presents to it:

```yaml
spec:
  credential:
    secretRef: {name: crm-api, key: token}   # a Secret in the server's own namespace
    header: Authorization                    # default
    scheme: Bearer                           # optional
```

Agents never hold it. With org namespaces, the registry grants it to the workload identities (SPIFFE IDs) of the Deployments whose Agent lists the server, in the server's own namespace only: in the org namespace, a policy `mcp-<…>` that reads only that Secret, and a role of the same name on the JWT auth method at `AGENT_REGISTRY_OPENBAO_WORKLOAD_AUTH_MOUNT` (default `jwt-spiffe`), bound to JWT-SVIDs with audience `AGENT_REGISTRY_OPENBAO_WORKLOAD_AUDIENCE` (default `openbao`) whose subject starts with one of those identities. A login token from it lives 60 seconds and can be used once. The gateway logs in with the calling agent's JWT-SVID after authorizing a tool call and reads the credential; OpenBao refuses any identity the registry did not grant.

The registry rebuilds the grants on every reconcile pass and after every identity change, and withdraws an identity's grants before its revocation is recorded; a revoked identity is never granted again. It writes, lists and deletes only policies and roles whose names start with `mcp-`, so its OpenBao policy in each org namespace needs:

```hcl
path "org-<org>/<mount>/*"                     { capabilities = ["create", "update", "read", "delete", "list"] }
path "org-<org>/sys/policies/acl/mcp-*"        { capabilities = ["create", "update", "read", "delete"] }
path "org-<org>/sys/policies/acl"              { capabilities = ["list"] }
path "org-<org>/auth/jwt-spiffe/role/mcp-*"    { capabilities = ["create", "update", "read", "delete"] }
path "org-<org>/auth/jwt-spiffe/role"          { capabilities = ["list"] }
path "sys/namespaces"                          { capabilities = ["list"] }
```
