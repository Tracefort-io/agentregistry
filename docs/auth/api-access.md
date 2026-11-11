# Calling the API with a token

With `AGENT_REGISTRY_AUTH_MODE=required`, every API call needs an access token from one of the issuers in `AGENT_REGISTRY_AUTH_ISSUERS`, for the registry's audience. People get one by signing in to the web UI. Scripts, CI pipelines and other services get one with the OAuth 2.0 **client credentials** grant and send it as a bearer token.

## 1. Register a client for the pipeline

In your identity provider, create a confidential client with client credentials enabled, and make its tokens:

- carry the registry's **audience** (one of `audiences` in `AUTH_ISSUERS`), and
- carry the **roles** your PDP policy checks (the issuer's `rolesClaim`, by default `realm_access.roles`).

The registry treats such a token as a client acting for itself: the AuthZEN subject has `"type": "client"`. A token is a client token when its `sub` equals its client ID, or when the issuer's `clientSubjectClaim` says so.

**Keycloak** (realm `tracefort`, audience `agentregistry`, role `registry-writer`):

```bash
kcadm.sh create clients -r tracefort -s clientId=ci-publisher \
  -s publicClient=false -s serviceAccountsEnabled=true \
  -s standardFlowEnabled=false -s directAccessGrantsEnabled=false
# Add the audience: assign the client scope that maps aud=agentregistry
kcadm.sh update clients/<client id>/default-client-scopes/<agentregistry-audience scope id> -r tracefort
# Grant the role to the client's service account
kcadm.sh add-roles -r tracefort --uusername service-account-ci-publisher --rolename registry-writer
# Read the secret
kcadm.sh get clients/<client id>/client-secret -r tracefort
```

**Microsoft Entra ID**: register an application, add a client secret or certificate, and grant it an **application** role exposed by the registry's app registration (for example `Registry.Publish`). Request the token with the scope `api://<registry app id>/.default`; set the issuer's `rolesClaim` to `roles`.

## 2. Get a token

```bash
TOKEN=$(curl -s https://auth.example.com/realms/tracefort/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=ci-publisher \
  --data-urlencode client_secret="$CI_PUBLISHER_SECRET" \
  | jq -r .access_token)
```

For Entra ID the token endpoint is `https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token`, with `-d scope=api://<registry app id>/.default`.

Tokens are short-lived: fetch a new one per pipeline run, not once per environment. Keep the client secret in your CI system's secret store.

## 3. Call the API

```bash
REGISTRY=https://registry.example.com

# Apply resources from YAML (the arctl apply format)
curl -s -X POST "$REGISTRY/v0/apply" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/yaml' \
  --data-binary @agent.yaml | jq '.results[] | {kind, name, status, error}'

# List what the client may read
curl -s "$REGISTRY/v0/agents?namespace=default" -H "Authorization: Bearer $TOKEN" | jq '.items[].metadata.name'

# What the client may do
curl -s "$REGISTRY/v0/me?namespace=default" -H "Authorization: Bearer $TOKEN" | jq '{admin, permissions}'
```

`POST /v0/apply` returns HTTP `200` with a result per document: check each `status` (`created`, `configured`, `unchanged`, or `failed` with an `error` such as `forbidden: ...`). Fail the pipeline on any `failed`:

```bash
curl -s -X POST "$REGISTRY/v0/apply" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/yaml' --data-binary @agent.yaml \
  | jq -e 'all(.results[]; .status != "failed")' >/dev/null
```

## arctl

`arctl` sends a token given with `--registry-token` or `ARCTL_API_TOKEN`:

```bash
export ARCTL_API_BASE_URL=https://registry.example.com
export ARCTL_API_TOKEN="$TOKEN"
arctl apply -f agent.yaml
```

## Responses

| Status | Meaning |
| --- | --- |
| `401` with `WWW-Authenticate: Bearer` | No token, or it is invalid, expired, from an untrusted issuer or for another audience |
| `403` | The PDP denied the operation |
| `404` | Not found, or the caller may not read it |
| `503` | The authorization service could not decide; retry later |
