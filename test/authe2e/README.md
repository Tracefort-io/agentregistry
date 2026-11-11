# Per-role access tests

`make test-auth-e2e` checks a running registry with `AGENT_REGISTRY_AUTH_MODE=required` against its real identity provider and AuthZEN PDP. For each role it checks what [authz-matrix.md](../../docs/auth/authz-matrix.md) and the reference policy [registry.rego](../../docs/auth/authzen/registry.rego) promise:

| Caller | Expected |
| --- | --- |
| Anonymous | `401` on the API and `/v0/me`; `alg=none` and HMAC tokens refused |
| `registry-admin` | `/v0/me` says `admin: true`; reads, lists, applies and deletes everything |
| `registry-writer` | `admin: false`; applies and deletes Prompts; reads Secrets without their values |
| `registry-reader` | reads and lists Prompts; applying or deleting is refused; Secrets cannot be listed (`403`) and a Secret reads as `404` |

The admin creates a Prompt and a Secret with random names first and deletes them at the end.

## Configuration

| Variable | Meaning |
| --- | --- |
| `AUTH_E2E_URLS` | Comma-separated base URLs. Test the gateway and the registry itself (a port-forward skips the gateway), so both layers are checked. |
| `AUTH_E2E_NAMESPACE` | Namespace for the test resources (default `default`). |
| `AUTH_E2E_KEEP` | `true` leaves everything the test creates in place for inspection. Deletes are then not exercised. |
| `AUTH_E2E_<ROLE>_TOKEN` | A bearer token for `ROLE` (`ADMIN`, `WRITER`, `READER`). Works with any IdP. |
| `AUTH_E2E_TOKEN_URL`, `AUTH_E2E_CLIENT_ID`, `AUTH_E2E_<ROLE>_USERNAME`, `AUTH_E2E_<ROLE>_PASSWORD` | Instead of tokens: get them with the OAuth 2.0 password grant (test realms only). |

A role without credentials is skipped. The admin is required.

## Example: Keycloak behind agentgateway on Kubernetes

```shell
kubectl -n tracefort-control-plane port-forward svc/agentregistry 18121:12121 &
AUTH_E2E_URLS=http://registry.tracefort.localhost:8081,http://127.0.0.1:18121 \
AUTH_E2E_TOKEN_URL=http://auth.tracefort.localhost/realms/tracefort/protocol/openid-connect/token \
AUTH_E2E_CLIENT_ID=tracefort-poc \
AUTH_E2E_ADMIN_USERNAME=alice  AUTH_E2E_ADMIN_PASSWORD=... \
AUTH_E2E_WRITER_USERNAME=carol AUTH_E2E_WRITER_PASSWORD=... \
AUTH_E2E_READER_USERNAME=bob   AUTH_E2E_READER_PASSWORD=... \
make test-auth-e2e
```

## Example: Microsoft Entra ID

Entra ID does not offer the password grant for most tenants, so pass tokens. Each test user (or app registration, for client-credentials tokens) needs an app role named `registry-admin`, `registry-writer` or `registry-reader`, and the registry's issuer entry must read roles from the `roles` claim:

```shell
AUTH_E2E_ADMIN_TOKEN=$(az account get-access-token --scope api://<registry-app-id>/.default --query accessToken -o tsv) \
AUTH_E2E_URLS=https://registry.example.com \
make test-auth-e2e
```
