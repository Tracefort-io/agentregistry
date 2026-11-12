import { describe, it, expect, vi } from "vitest"
import { createClient } from "@/lib/api/client"
import { actorLabel, auditQuery, fetchAuditPage, NO_FILTERS, PAGE_SIZE, resourceLabel } from "../audit"

function apiReturning(status: number, body?: unknown) {
  const fetchFn = vi.fn(async (_request: Request) => new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  }))
  return { api: createClient({ baseUrl: "http://registry", fetch: fetchFn as unknown as typeof fetch }), fetchFn }
}

describe("auditQuery", () => {
  it("sends only the filters that are set, trimmed", () => {
    expect(auditQuery({ ...NO_FILTERS, actor: " alice ", outcome: "denied" }, "")).toEqual({
      limit: PAGE_SIZE, actor: "alice", outcome: "denied",
    })
  })

  it("adds the cursor for the next page", () => {
    expect(auditQuery(NO_FILTERS, "abc")).toEqual({ limit: PAGE_SIZE, cursor: "abc" })
  })
})

describe("fetchAuditPage", () => {
  const event = {
    id: 3, time: "2026-11-11T09:00:00Z", action: "apply", outcome: "success", detail: "created",
    actor: { subject: "s", username: "alice" }, resource: { kind: "Prompt", namespace: "default", name: "p" },
  }

  it("asks for the filtered page and returns events and cursor", async () => {
    const { api, fetchFn } = apiReturning(200, { events: [event], nextCursor: "next" })
    const page = await fetchAuditPage(api, { ...NO_FILTERS, kind: "Prompt" }, "c1")
    const url = new URL(fetchFn.mock.calls[0][0].url)
    expect(url.pathname).toBe("/v0/audit")
    expect(url.searchParams.get("kind")).toBe("Prompt")
    expect(url.searchParams.get("cursor")).toBe("c1")
    expect(page).toEqual({ events: [event], nextCursor: "next", error: "" })
  })

  it.each([
    [403, "Only registry admins"],
    [404, "turned off"],
    [500, "HTTP 500"],
  ])("explains HTTP %i", async (status, want) => {
    const page = await fetchAuditPage(apiReturning(status, { title: "x" }).api, NO_FILTERS)
    expect(page.events).toEqual([])
    expect(page.error).toContain(want)
  })
})

describe("labels", () => {
  it.each([
    [{ username: "alice", subject: "s" }, "alice"],
    [{ subject: "svc-account" }, "svc-account"],
    [{}, "anonymous"],
    [{ username: "alice", via: ["agent-1"] }, "alice (via agent-1)"],
  ])("actor %j -> %s", (actor, want) => {
    expect(actorLabel(actor)).toBe(want)
  })

  it.each([
    [{ kind: "Prompt", namespace: "team", name: "p", tag: "v1" }, "team/p@v1"],
    [{ kind: "Prompt", name: "p" }, "default/p"],
    [{ kind: "Secret", namespace: "team" }, "team/*"],
    [{ kind: "Secret" }, "*"],
  ])("resource %j -> %s", (resource, want) => {
    expect(resourceLabel(resource)).toBe(want)
  })
})
