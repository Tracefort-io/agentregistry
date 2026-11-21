# Rego policies

The registry gives policy authors a place to write, test and publish the Rego policies that OPA enforces. The policies live in a GitHub or GitLab repository, not in the registry:

- **The repository** holds the policies and their data. It keeps the history, and its branch protection decides who may merge.
- **The registry** reads the repository live, provides an editor to change and test policies, and publishes each change as a pull request (a merge request on GitLab).
- **An approver** reviews and merges the pull request on GitHub or GitLab.
- **OPAL** tracks the branch and loads what is merged into OPA.
- **The registry** tags each merged change as the policy's next version.

```
editor ──► POST /v0/policies/{name}/publish ──► branch + commit ──► pull request
                                                                       │ approver merges
                                                                       ▼
OPA ◄── OPAL client ◄── OPAL server ◄── tracked branch (main) ──► webhook ──► tag <policy>/v<N>
```

## Repository layout

Each top-level directory of the repository is a policy. It holds `.rego` files and `data.json` files, laid out as in an OPA bundle:

```
authzen/
  registry.rego          package authzen
  registry_test.rego     package authzen_test
  data.json              loaded at data.authzen
  roles/data.json        loaded at data.authzen.roles
system/
  authz.rego             package system.authz
```

- A directory is a policy only if it holds at least one `.rego` file and its name matches `^[a-z0-9][a-z0-9_-]{0,62}$`. Files at the repository root, such as a README, are left alone.
- A data file is loaded under its directory, as OPA and OPAL do.
- Data files must be named `data.json`. OPAL's git tracking loads `data.json` files but not `data.yaml`, so the registry refuses `data.yaml`.
- The registry only writes `.rego` and `data.json` files.

## Versions

Every merged change gets a tag `<policy>/v<N>` on its merge commit. The first merge is `v1`, and `N` counts up from the highest existing tag.

1. When a pull request is merged into the tracked branch, the git host calls `POST /policies/webhook`.
2. The registry lists the files the pull request changed.
3. For each policy among them, it tags the merge commit.

A redelivered webhook changes nothing, because a policy already tagged on that commit is skipped. If two deliveries race for the same number, the loser retries with the next one.

Versions are git tags, so they're visible in GitHub or GitLab too. Restoring an older version in the editor loads its files as a new draft; publishing it makes them the next version. History is never rewritten.

## Who may do what

The AuthZEN PDP decides, like every other registry operation. Its checks use `{"type": "policy", "id": "<policy>"}`:

| Operation | Action |
| --- | --- |
| List, read, versions, diff, pending changes, OPA status | `read` on the policy; a list shows only the policies the caller may read |
| Format, check, evaluate, test (the editor's tools) | `read` on the policy |
| Publish (open a pull request) | `apply` on the policy |

The reference policy ([registry.rego](auth/authzen/registry.rego)) gives these to `registry-admin` and to a `policy-author` role. Writers and readers get nothing on policies.

Merging is not the registry's decision. Protect the tracked branch on the git host, for example:

- require a pull request and an approving review before merging;
- use CODEOWNERS for the policy directories;
- block direct pushes.

The registry's token needs to push branches and tags, but must not be able to bypass that protection.

## The editor

The UI's Policies page lists the policies, and the editor works like the [Rego Playground](https://play.openpolicyagent.org/):

- **Files:** a tab for each file, with a Rego editor.
- **Check:** compiles the draft and reports problems inline in the editor.
- **Format:** formats the open file as `opa fmt` does.
- **Evaluate:** runs a query against the draft with the INPUT and DATA panels. DATA is merged over the policy's own data files. The default INPUT is a request the registry sends its PDP.
- **Test:** runs the draft's `test_` rules.
- **Publish:** opens a pull request with the changed files and a commit message. Its first line becomes the pull request's title.
- **Versions and pending changes:** what each version changed, and the open pull requests that touch the policy.
- **OPA badge:** which version OPA has loaded, when `POLICIES_OPA_URL` is set.

Format, Check, Evaluate and Test run in the registry with the OPA Go library, on Rego that users wrote. They are restricted:

- `http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed, so a draft that uses them doesn't compile;
- each run is limited to `POLICIES_EVAL_TIMEOUT`;
- request bodies are capped by `HTTP_MAX_BODY_BYTES`.

Publish runs the same check and refuses a draft with problems. The commit's author is the signed-in user, its committer is `POLICIES_COMMITTER_NAME`, and its message ends with `Published-by: <subject> (<issuer>)`.

## Setting it up

### 1. The repository and a token

Create the repository, then a token for the registry:

- **GitHub:** a fine-grained token for the repository with *Contents: read and write* and *Pull requests: read and write*. A GitHub App installation token also works.
- **GitLab:** a project access token with the `api` scope and the Developer role.

Store the token in a registry Secret, which goes in the configured secret store, such as OpenBao:

```yaml
apiVersion: ar.dev/v1alpha1
kind: Secret
metadata:
  name: policies-git
  namespace: default
spec:
  stringData:
    password: <token>
```

A token-only Secret is sent as `x-access-token:<token>` on GitHub and `oauth2:<token>` on GitLab. Set `username` in the Secret to use another user name.

### 2. The webhook

On the repository, add a webhook to `https://<registry>/policies/webhook`:

- **GitHub:** content type `application/json`, the secret, and the *Pull requests* event.
- **GitLab:** the secret token and *Merge request events*.

The registry checks `X-Hub-Signature-256` (GitHub) or `X-Gitlab-Token` (GitLab). Without a valid signature it refuses the delivery. If tagging fails, the delivery fails and can be redelivered from the host.

### 3. The registry

| Setting (`AGENT_REGISTRY_…`) | Chart value (`policies.…`) | Meaning |
| --- | --- | --- |
| `POLICIES_ENABLED` | `enabled` | Turns the feature on. Needs `AUTH_MODE=required`. |
| `POLICIES_PROVIDER` | `provider` | `github` or `gitlab` |
| `POLICIES_REPO_URL` | `repoUrl` | The repository's https URL |
| `POLICIES_BRANCH` | `branch` | The branch OPAL tracks (default `main`) |
| `POLICIES_API_URL` | `apiUrl` | Overrides the API URL derived from the repository URL |
| `POLICIES_CREDENTIALS_SECRET` | `credentialsSecret` | The registry Secret with the token, `<name>` or `<namespace>/<name>` |
| `POLICIES_WEBHOOK_SECRET_FILE` | `webhookSecretRef` | A file (a Kubernetes Secret in the chart) with the webhook secret, at least 32 bytes |
| `POLICIES_COMMITTER_NAME`, `POLICIES_COMMITTER_EMAIL` | `committer` | The committer of the registry's commits |
| `POLICIES_OPA_URL`, `POLICIES_OPA_TOKEN_FILE`, `POLICIES_OPA_CA_CERT_FILE` | `opa` | Optional: the OPA to compare with, for the OPA badge; the CA file (chart: `opa.caConfigMapRef`) is for an OPA whose certificate comes from a private CA |
| `POLICIES_EVAL_TIMEOUT` | `evalTimeout` | Time limit for one Evaluate or Test run (default `5s`) |

The token is read from the Secret on every call, so a rotated token takes effect at once.

### 4. OPAL

Point the OPAL server at the same repository and branch, for example:

```
OPAL_POLICY_REPO_URL=https://github.com/acme/policies.git
OPAL_POLICY_REPO_MAIN_BRANCH=main
OPAL_POLICY_REPO_WEBHOOK_SECRET=<secret>        # or OPAL_POLICY_REPO_POLLING_INTERVAL=30
```

OPAL loads every `.rego` file and every `data.json` file under its directory. The registry doesn't talk to OPAL; it only reads OPA's `GET /v1/policies` for the OPA badge.

### 5. The PDP policy

Give authors the `policy-author` role, or merge the `policy` rule from [registry.rego](auth/authzen/registry.rego) into your policy. Until then the PDP denies every policy operation to everyone except `registry-admin`.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /v0/policies` | Policies on the tracked branch |
| `GET /v0/policies/{name}?ref=` | Files at the branch head, a version (`v3`) or a commit, with the commit read |
| `GET /v0/policies/{name}/versions` | Versions, newest first |
| `GET /v0/policies/{name}/diff?from=&to=` | Files that differ between two refs |
| `GET /v0/policies/{name}/pending` | Open pull requests that change the policy |
| `GET /v0/policies/{name}/status` | Which version OPA has loaded |
| `POST /v0/policies/{name}/publish` | `{baseCommit, files, message}`: opens a pull request; `null` deletes a file |
| `POST /v0/policies/{name}/format`, `/check`, `/evaluate`, `/test` | The editor's tools, on a draft sent in the body |
| `POST /policies/webhook` | Merge webhooks from the git host (signature, no token) |

Publishing and tagging are recorded in the audit log as `publish-policy` and `tag-policy`.

## Limits

- The registry reads the repository on every request, with no index. Large repositories are slow, and reads are capped at 32 MiB and 5000 files.
- A publish is capped at 512 KiB per file and 1 MiB in all, and by `HTTP_MAX_BODY_BYTES`.
- Lint is the compiler's checks only; Regal isn't included.
- The OPA badge compares Rego contents, not data, and only the latest 10 versions.
- A data file at the repository root (loaded at `data`) isn't part of any policy and can't be edited here.
