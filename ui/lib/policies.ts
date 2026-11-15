import { client } from "@/lib/admin-api"

type Api = Pick<typeof client, "get" | "post">

// PolicySummary is one policy in the repository: a top-level directory of
// Rego and data files.
export interface PolicySummary {
  name: string
  packages: string[]
  dataPaths: string[]
  files: number
  latestVersion?: string
}

export interface PolicyFile {
  path: string
  content: string
}

// Policy is a policy's files at one commit; publishing edits on top of it.
export interface Policy extends Omit<PolicySummary, "files"> {
  commit: string
  ref: string
  files: PolicyFile[]
}

export interface PolicyVersion {
  version: string
  tag: string
  commit: string
  author: string
  date: string
  message: string
}

export interface PolicyChange {
  path: string
  old?: string
  new?: string
}

export interface PullRequest {
  number: number
  title: string
  url: string
  author: string
  headBranch: string
  baseBranch: string
  createdAt: string
}

export interface PolicyStatus {
  checked: boolean
  loaded: boolean
  liveVersion?: string
  headLoaded: boolean
}

export interface Problem {
  file?: string
  row?: number
  col?: number
  message: string
}

export interface EvalResult {
  query: string
  result?: { expressions: { value: unknown; text: string }[]; bindings?: Record<string, unknown> }[] | null
  output?: string
  problems?: Problem[]
  durationNs: number
}

export interface TestResult {
  file: string
  row: number
  package: string
  name: string
  pass: boolean
  skip?: boolean
  error?: string
  output?: string
  durationNs: number
}

export interface TestReport {
  results: TestResult[]
  problems?: Problem[]
  passed: number
  failed: number
}

export interface PublishResult {
  pullRequest: PullRequest
  branch: string
  commit: string
}

// Result is a value, or why it couldn't be had.
export type Result<T> = { ok: true; value: T } | { ok: false; error: string }

// Draft is the editor's working copy: file contents by path in the policy.
export type Draft = Record<string, string>

const json = { "Content-Type": "application/json" }

function explain(status: number | undefined, what: string, detail?: string): string {
  if (status === 404 && !detail) return "Policies are not enabled on this registry."
  if (status === 401) return "Sign in to use policies."
  if (status === 403) return `You may not ${what}.`
  if (status === 502) return "The policy repository is unavailable. Try again later."
  if (detail) return detail
  return `Could not ${what} (HTTP ${status ?? "error"}).`
}

// detailOf reads a problem response's detail.
function detailOf(error: unknown): string | undefined {
  if (error && typeof error === "object" && "detail" in error && typeof error.detail === "string") return error.detail
  return undefined
}

async function get<T>(api: Api, url: string, what: string, query?: Record<string, string>): Promise<Result<T>> {
  const { data, error, response } = await api.get<{ 200: T }, unknown, false>({ url, query })
  if (!response?.ok || data === undefined) return { ok: false, error: explain(response?.status, what, detailOf(error)) }
  return { ok: true, value: data as T }
}

async function post<T>(api: Api, url: string, body: unknown, what: string): Promise<Result<T>> {
  const { data, error, response } = await api.post<{ 200: T; 201: T }, unknown, false>({ url, body, headers: json })
  if (!response?.ok || data === undefined) return { ok: false, error: explain(response?.status, what, detailOf(error)) }
  return { ok: true, value: data as T }
}

const base = (name: string) => `/v0/policies/${encodeURIComponent(name)}`

export async function fetchPolicies(api: Api): Promise<Result<PolicySummary[]>> {
  const r = await get<{ policies?: PolicySummary[] }>(api, "/v0/policies", "list policies")
  return r.ok ? { ok: true, value: r.value.policies ?? [] } : r
}

// fetchPolicy reads a policy at ref: "" for the tracked branch, a version, or a commit.
export function fetchPolicy(api: Api, name: string, ref = ""): Promise<Result<Policy>> {
  return get<Policy>(api, base(name), "read this policy", ref ? { ref } : undefined)
}

export async function fetchVersions(api: Api, name: string): Promise<Result<PolicyVersion[]>> {
  const r = await get<{ versions?: PolicyVersion[] }>(api, `${base(name)}/versions`, "list versions")
  return r.ok ? { ok: true, value: r.value.versions ?? [] } : r
}

export async function fetchDiff(api: Api, name: string, from: string, to: string): Promise<Result<PolicyChange[]>> {
  const r = await get<{ changes?: PolicyChange[] }>(api, `${base(name)}/diff`, "compare versions", { from, to })
  return r.ok ? { ok: true, value: r.value.changes ?? [] } : r
}

export async function fetchPending(api: Api, name: string): Promise<Result<PullRequest[]>> {
  const r = await get<{ pullRequests?: PullRequest[] }>(api, `${base(name)}/pending`, "list pending changes")
  return r.ok ? { ok: true, value: r.value.pullRequests ?? [] } : r
}

export function fetchStatus(api: Api, name: string): Promise<Result<PolicyStatus>> {
  return get<PolicyStatus>(api, `${base(name)}/status`, "read what OPA has loaded")
}

export function formatFile(api: Api, name: string, path: string, content: string): Promise<Result<{ content?: string; problems: Problem[] }>> {
  return post(api, `${base(name)}/format`, { path, content }, "format this file")
}

export async function checkDraft(api: Api, name: string, files: Draft): Promise<Result<Problem[]>> {
  const r = await post<{ problems?: Problem[] }>(api, `${base(name)}/check`, { files }, "check this policy")
  return r.ok ? { ok: true, value: r.value.problems ?? [] } : r
}

export function evaluateDraft(api: Api, name: string, files: Draft, query: string, input: unknown, data: unknown): Promise<Result<EvalResult>> {
  const body: Record<string, unknown> = { files, query }
  if (input !== undefined) body.input = input
  if (data !== undefined) body.data = data
  return post(api, `${base(name)}/evaluate`, body, "evaluate this policy")
}

export function testDraft(api: Api, name: string, files: Draft, data: unknown): Promise<Result<TestReport>> {
  const body: Record<string, unknown> = { files }
  if (data !== undefined) body.data = data
  return post(api, `${base(name)}/test`, body, "test this policy")
}

// publishDraft opens a pull request with the files that differ from the
// policy as loaded; a file removed from the draft is deleted.
export function publishDraft(api: Api, policy: Policy, draft: Draft, message: string): Promise<Result<PublishResult>> {
  return post(api, `${base(policy.name)}/publish`, {
    baseCommit: policy.commit, files: changedFiles(policy, draft), message,
  }, "publish this policy")
}

// changedFiles maps each changed path to its new content, or null when deleted.
export function changedFiles(policy: Policy, draft: Draft): Record<string, string | null> {
  const out: Record<string, string | null> = {}
  const original = new Map(policy.files.map((f) => [f.path, f.content]))
  for (const [path, content] of Object.entries(draft)) {
    if (original.get(path) !== content) out[path] = content
  }
  for (const path of original.keys()) {
    if (!(path in draft)) out[path] = null
  }
  return out
}

// parseJSON reads an editor panel: empty is undefined.
export function parseJSON(text: string, what: string): Result<unknown> {
  if (!text.trim()) return { ok: true, value: undefined }
  try {
    return { ok: true, value: JSON.parse(text) }
  } catch (e) {
    return { ok: false, error: `${what} is not valid JSON: ${e instanceof Error ? e.message : String(e)}` }
  }
}

// isPolicyFile accepts the files a policy may hold, as the registry does.
export function isPolicyFile(path: string): boolean {
  if (!path || path.startsWith("/") || path.split("/").some((p) => p === "" || p === "." || p === ".." || p.startsWith("."))) return false
  const base = path.split("/").pop() ?? ""
  return path.endsWith(".rego") || base === "data.json"
}

// sampleInput is a request the registry sends its PDP, to start from.
export const sampleInput = {
  subject: { type: "user", id: "alice", properties: { iss: "https://idp.example.com", roles: ["registry-reader"], groups: [] } },
  action: { name: "read" },
  resource: { type: "agent", id: "default/my-agent", properties: { kind: "Agent", namespace: "default", name: "my-agent" } },
  context: { pep: "agentregistry" },
}
