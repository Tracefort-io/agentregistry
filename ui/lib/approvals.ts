import { client } from "@/lib/admin-api"

type Api = Pick<typeof client, "get" | "post">

// ApprovalRequest is a change the registry holds until it is approved.
export interface ApprovalRequest {
  id: string
  status: "pending" | "approved" | "applying" | "applied" | "failed" | "stale" | "denied" | "expired" | "cancelled"
  verb: "apply" | "delete"
  kind: string
  namespace: string
  name: string
  tag?: string
  document?: unknown
  requesterSubject: string
  requesterUsername?: string
  approvalId?: string
  detail?: string
  createdAt: string
  updatedAt: string
}

// ApprovalReview is a request awaiting the signed-in approver: the access
// request service's task, and the change it would apply.
export interface ApprovalReview {
  task: {
    id: string
    status: string
    display?: { title?: string }
    request?: { requester?: { sub?: string }; subject?: { id?: string; properties?: { username?: string } } }
    decisions?: { approver?: { sub?: string }; decision: string; comment?: string }[]
  }
  change?: ApprovalRequest
}

export interface Loaded<T> {
  items: T[]
  error: string
}

// explain turns a status into a message for the page.
function explain(status: number | undefined, what: string): string {
  if (status === 404) return "Approvals are not enabled on this registry."
  if (status === 403) return `You may not ${what}.`
  if (status === 502) return "The approval service is unavailable. Try again later."
  return `Could not ${what} (HTTP ${status ?? "error"}).`
}

// fetchMyRequests lists the signed-in user's held changes, newest first.
export async function fetchMyRequests(api: Api): Promise<Loaded<ApprovalRequest>> {
  const { data, response } = await api.get<{ 200: { requests?: ApprovalRequest[] } }, unknown, false>({ url: "/v0/approvals", query: { limit: 200 } })
  if (!response?.ok) return { items: [], error: explain(response?.status, "load your requests") }
  return { items: data?.requests ?? [], error: "" }
}

// fetchReviews lists the requests awaiting the signed-in approver.
export async function fetchReviews(api: Api): Promise<Loaded<ApprovalReview>> {
  const { data, response } = await api.get<{ 200: { reviews?: ApprovalReview[] } }, unknown, false>({ url: "/v0/approval-reviews" })
  if (!response?.ok) return { items: [], error: explain(response?.status, "load requests to review") }
  return { items: data?.reviews ?? [], error: "" }
}

// cancelRequest withdraws a pending request.
export async function cancelRequest(api: Api, id: string): Promise<string> {
  const { response } = await api.post<{ 200: ApprovalRequest }, unknown, false>({
    url: `/v0/approvals/${encodeURIComponent(id)}/cancel`, body: {}, headers: { "Content-Type": "application/json" },
  })
  if (response?.status === 409) return "The request was already decided."
  return response?.ok ? "" : explain(response?.status, "withdraw this request")
}

// decide approves or denies a request; the registry applies an approved change.
export async function decide(api: Api, id: string, decision: "approve" | "deny", comment: string): Promise<string> {
  const body: { decision: string; comment?: string } = { decision }
  if (comment.trim()) body.comment = comment.trim()
  const { response } = await api.post<{ 200: ApprovalReview }, unknown, false>({
    url: `/v0/approval-reviews/${encodeURIComponent(id)}/decision`, body, headers: { "Content-Type": "application/json" },
  })
  if (response?.status === 403) return "You may not decide this request. Nobody approves their own change."
  if (response?.status === 409) return "The request was already decided, or you already voted."
  return response?.ok ? "" : explain(response?.status, "record the decision")
}

// changeLabel names a held change, such as "apply Deployment prod/bot".
export function changeLabel(r: Pick<ApprovalRequest, "verb" | "kind" | "namespace" | "name" | "tag">): string {
  const path = `${r.namespace || "default"}/${r.name}${r.tag ? `@${r.tag}` : ""}`
  return `${r.verb} ${r.kind} ${path}`
}

// isOpen reports a request that may still change.
export function isOpen(status: ApprovalRequest["status"]): boolean {
  return status === "pending" || status === "approved" || status === "applying"
}
