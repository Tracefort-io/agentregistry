import { describe, it, expect, vi } from "vitest"
import { createClient } from "@/lib/api/client"
import { cancelRequest, changeLabel, decide, fetchMyRequests, fetchReviews, isOpen } from "../approvals"

function apiReturning(status: number, body?: unknown) {
  const fetchFn = vi.fn(async (_request: Request) => new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  }))
  return { api: createClient({ baseUrl: "http://registry", fetch: fetchFn as unknown as typeof fetch }), fetchFn }
}

const held = {
  id: "arq_1", status: "pending", verb: "apply", kind: "Deployment", namespace: "prod", name: "bot",
  requesterSubject: "carol-sub", createdAt: "2026-11-12T09:00:00Z", updatedAt: "2026-11-12T09:00:00Z",
}

describe("fetchMyRequests", () => {
  it("lists the user's requests", async () => {
    const { api, fetchFn } = apiReturning(200, { requests: [held] })
    const got = await fetchMyRequests(api)
    expect(new URL(fetchFn.mock.calls[0][0].url).pathname).toBe("/v0/approvals")
    expect(got).toEqual({ items: [held], error: "" })
  })

  it.each([
    [404, "not enabled"],
    [502, "unavailable"],
    [500, "HTTP 500"],
  ])("explains HTTP %i", async (status, want) => {
    expect((await fetchMyRequests(apiReturning(status, {}).api)).error).toContain(want)
  })
})

describe("fetchReviews", () => {
  it("lists the requests awaiting the approver", async () => {
    const review = { task: { id: "arq_1", status: "pending", display: { title: "apply deployment prod/bot" } }, change: held }
    const { api, fetchFn } = apiReturning(200, { reviews: [review] })
    expect((await fetchReviews(api)).items).toEqual([review])
    expect(new URL(fetchFn.mock.calls[0][0].url).pathname).toBe("/v0/approval-reviews")
  })
})

describe("decide", () => {
  it("sends the decision and comment", async () => {
    const { api, fetchFn } = apiReturning(200, { task: { id: "arq_1", status: "approved" } })
    expect(await decide(api, "arq_1", "approve", "  looks good ")).toBe("")
    const req = fetchFn.mock.calls[0][0]
    expect(new URL(req.url).pathname).toBe("/v0/approval-reviews/arq_1/decision")
    expect(await req.json()).toEqual({ decision: "approve", comment: "looks good" })
  })

  it.each([
    [403, "own change"],
    [409, "already decided"],
  ])("explains HTTP %i", async (status, want) => {
    expect(await decide(apiReturning(status, {}).api, "arq_1", "deny", "")).toContain(want)
  })
})

describe("cancelRequest", () => {
  it("withdraws a pending request", async () => {
    const { api, fetchFn } = apiReturning(200, { ...held, status: "cancelled" })
    expect(await cancelRequest(api, "arq_1")).toBe("")
    expect(new URL(fetchFn.mock.calls[0][0].url).pathname).toBe("/v0/approvals/arq_1/cancel")
  })

  it("explains a request already decided", async () => {
    expect(await cancelRequest(apiReturning(409, {}).api, "arq_1")).toContain("already decided")
  })
})

describe("labels", () => {
  it("names a change", () => {
    expect(changeLabel({ verb: "apply", kind: "Deployment", namespace: "prod", name: "bot" })).toBe("apply Deployment prod/bot")
    expect(changeLabel({ verb: "delete", kind: "Agent", namespace: "", name: "a", tag: "v2" })).toBe("delete Agent default/a@v2")
  })

  it.each([
    ["pending", true], ["approved", true], ["applying", true],
    ["applied", false], ["denied", false], ["cancelled", false], ["failed", false],
  ] as const)("%s open: %s", (status, want) => {
    expect(isOpen(status)).toBe(want)
  })
})
