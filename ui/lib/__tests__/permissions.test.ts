import { describe, it, expect, vi } from "vitest"
import { createClient } from "@/lib/api/client"
import { canFrom, loadCan, PERMISSIONS_NAMESPACE } from "../permissions"

function apiReturning(status: number, body?: unknown) {
  const fetchFn = vi.fn(async (_request: Request) => new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  }))
  return { api: createClient({ baseUrl: "http://registry", fetch: fetchFn as unknown as typeof fetch }), fetchFn }
}

describe("canFrom", () => {
  const can = canFrom({
    enforced: true,
    admin: false,
    permissions: { Agent: ["read", "list"], Deployment: ["read", "list", "apply", "delete"] },
  })

  it.each([
    ["Agent", "list", true],
    ["Agent", "apply", false],
    ["Agent", "deploy", false],
    ["Deployment", "delete", true],
    ["Secret", "read", false],
  ] as const)("%s %s -> %s", (kind, action, want) => {
    expect(can(kind, action)).toBe(want)
  })
})

describe("loadCan", () => {
  it("asks /v0/me about the namespace new resources go to", async () => {
    const { api, fetchFn } = apiReturning(200, { enforced: true, admin: false, permissions: { Prompt: ["read", "apply"] } })
    const can = await loadCan(api)
    const request = fetchFn.mock.calls[0][0]
    expect(request.url).toBe(`http://registry/v0/me?namespace=${PERMISSIONS_NAMESPACE}`)
    expect(can("Prompt", "apply")).toBe(true)
    expect(can("Prompt", "delete")).toBe(false)
  })

  it("shows every action on a registry without /v0/me", async () => {
    const can = await loadCan(apiReturning(404).api)
    expect(can("Agent", "deploy")).toBe(true)
  })

  it.each([503, 500, 401])("hides every action when the answer is unavailable (%i)", async (status) => {
    const can = await loadCan(apiReturning(status, { title: "unavailable" }).api)
    expect(can("Agent", "read")).toBe(false)
  })

  it("hides every action on a malformed answer", async () => {
    const can = await loadCan(apiReturning(200, { enforced: true }).api)
    expect(can("Agent", "read")).toBe(false)
  })
})
