import { client } from "@/lib/admin-api"

// AuditEvent is one record from GET /v0/audit.
export interface AuditEvent {
  id: number
  time: string
  requestId?: string
  actor: { subject?: string; issuer?: string; username?: string; client?: boolean; via?: string[] }
  action: "apply" | "delete" | "read" | "list" | "request-approval"
  resource: { kind: string; namespace?: string; name?: string; tag?: string }
  outcome: "success" | "denied" | "failure"
  detail?: string
  source?: string
}

// AuditFilters narrow the log. Empty fields match everything.
export interface AuditFilters {
  actor: string
  action: string
  outcome: string
  kind: string
  namespace: string
  name: string
}

export const NO_FILTERS: AuditFilters = { actor: "", action: "", outcome: "", kind: "", namespace: "", name: "" }

export const PAGE_SIZE = 50

export interface AuditPage {
  events: AuditEvent[]
  nextCursor: string
  error: string
}

// auditQuery is the query string for one page: trimmed filters, without
// empty ones, plus the page size and cursor.
export function auditQuery(filters: AuditFilters, cursor: string): Record<string, string | number> {
  const query: Record<string, string | number> = { limit: PAGE_SIZE }
  for (const [key, value] of Object.entries(filters)) {
    const v = value.trim()
    if (v) query[key] = v
  }
  if (cursor) query.cursor = cursor
  return query
}

// fetchAuditPage loads one page of the log, newest first.
export async function fetchAuditPage(
  api: Pick<typeof client, "get">,
  filters: AuditFilters,
  cursor = "",
): Promise<AuditPage> {
  const { data, response } = await api.get<{ 200: { events?: AuditEvent[]; nextCursor?: string } }, unknown, false>({
    url: "/v0/audit",
    query: auditQuery(filters, cursor),
  })
  if (response?.status === 403) {
    return { events: [], nextCursor: "", error: "Only registry admins can read the audit log." }
  }
  if (response?.status === 404) {
    return { events: [], nextCursor: "", error: "The audit log is turned off on this registry." }
  }
  if (!response?.ok) {
    return { events: [], nextCursor: "", error: `Could not load the audit log (HTTP ${response?.status ?? "error"}).` }
  }
  return { events: data?.events ?? [], nextCursor: data?.nextCursor ?? "", error: "" }
}

// actorLabel names who acted: the username, else the subject.
export function actorLabel(actor: AuditEvent["actor"]): string {
  const who = actor.username || actor.subject || "anonymous"
  return actor.via?.length ? `${who} (via ${actor.via.join(", ")})` : who
}

// resourceLabel names what was acted on, as namespace/name@tag, or
// namespace/* for a list.
export function resourceLabel(resource: AuditEvent["resource"]): string {
  if (!resource.name) return resource.namespace ? `${resource.namespace}/*` : "*"
  const path = `${resource.namespace || "default"}/${resource.name}`
  return resource.tag ? `${path}@${resource.tag}` : path
}
