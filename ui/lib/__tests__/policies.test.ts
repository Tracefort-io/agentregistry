import { describe, it, expect, vi } from "vitest"
import { createClient } from "@/lib/api/client"
import {
  changedFiles, evaluateDraft, fetchPolicies, fetchPolicy, isPolicyFile, parseJSON, publishDraft, type Policy,
} from "../policies"

function apiReturning(status: number, body?: unknown) {
  const fetchFn = vi.fn(async (_request: Request) => new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  }))
  return { api: createClient({ baseUrl: "http://registry", fetch: fetchFn as unknown as typeof fetch }), fetchFn }
}

const policy: Policy = {
  name: "authzen", packages: ["authzen"], dataPaths: ["data.authzen"], commit: "a".repeat(40), ref: "main",
  files: [{ path: "registry.rego", content: "package authzen\n" }, { path: "data.json", content: "{}" }],
}

describe("fetchPolicies", () => {
  it("lists policies", async () => {
    const { api, fetchFn } = apiReturning(200, { policies: [{ name: "authzen", packages: [], dataPaths: [], files: 2 }] })
    const r = await fetchPolicies(api)
    expect(new URL(fetchFn.mock.calls[0][0].url).pathname).toBe("/v0/policies")
    expect(r).toEqual({ ok: true, value: [{ name: "authzen", packages: [], dataPaths: [], files: 2 }] })
  })

  it.each([
    [404, "not enabled"],
    [403, "may not list policies"],
    [502, "unavailable"],
    [500, "HTTP 500"],
  ])("explains HTTP %i", async (status, want) => {
    const r = await fetchPolicies(apiReturning(status, {}).api)
    expect(r.ok ? "" : r.error).toContain(want)
  })
})

describe("fetchPolicy", () => {
  it("asks for a ref and passes on the server's detail", async () => {
    const { api, fetchFn } = apiReturning(404, { detail: "not found: v9" })
    const r = await fetchPolicy(api, "authzen", "v9")
    const url = new URL(fetchFn.mock.calls[0][0].url)
    expect(url.pathname).toBe("/v0/policies/authzen")
    expect(url.searchParams.get("ref")).toBe("v9")
    expect(r).toEqual({ ok: false, error: "not found: v9" })
  })
})

describe("changedFiles", () => {
  it("lists changed, added and deleted files", () => {
    expect(changedFiles(policy, { "registry.rego": "package authzen\n\nallow := true\n", "new.rego": "package x\n" })).toEqual({
      "registry.rego": "package authzen\n\nallow := true\n", "new.rego": "package x\n", "data.json": null,
    })
    expect(changedFiles(policy, { "registry.rego": "package authzen\n", "data.json": "{}" })).toEqual({})
  })
})

describe("publishDraft", () => {
  it("sends only the changes, on top of the policy's commit", async () => {
    const { api, fetchFn } = apiReturning(201, { pullRequest: { number: 7, url: "https://git/pr/7" }, branch: "policy/authzen/x", commit: "b" })
    const r = await publishDraft(api, policy, { "registry.rego": "package authzen\n", "data.json": "{\"a\":1}" }, "authzen: data")
    const req = fetchFn.mock.calls[0][0]
    expect(new URL(req.url).pathname).toBe("/v0/policies/authzen/publish")
    expect(await req.json()).toEqual({ baseCommit: "a".repeat(40), files: { "data.json": "{\"a\":1}" }, message: "authzen: data" })
    expect(r.ok && r.value.pullRequest.number).toBe(7)
  })

  it("shows why a publish was refused", async () => {
    const r = await publishDraft(apiReturning(422, { detail: "invalid request: authzen/registry.rego:3:1: var x is unsafe" }).api, policy, {}, "m")
    expect(r).toEqual({ ok: false, error: "invalid request: authzen/registry.rego:3:1: var x is unsafe" })
  })
})

describe("evaluateDraft", () => {
  it("leaves out empty input and data", async () => {
    const { api, fetchFn } = apiReturning(200, { query: "data.authzen", result: [], durationNs: 1 })
    await evaluateDraft(api, "authzen", { "a.rego": "package authzen\n" }, "", undefined, undefined)
    expect(await fetchFn.mock.calls[0][0].json()).toEqual({ files: { "a.rego": "package authzen\n" }, query: "" })
  })
})

describe("parseJSON", () => {
  it("reads JSON and treats blank as undefined", () => {
    expect(parseJSON(" ", "INPUT")).toEqual({ ok: true, value: undefined })
    expect(parseJSON('{"a":1}', "INPUT")).toEqual({ ok: true, value: { a: 1 } })
    const bad = parseJSON("{a", "DATA")
    expect(bad.ok ? "" : bad.error).toContain("DATA is not valid JSON")
  })
})

describe("isPolicyFile", () => {
  it.each([
    ["registry.rego", true],
    ["lib/util.rego", true],
    ["roles/data.json", true],
    ["data.json", true],
    ["data.yaml", false],
    ["run.sh", false],
    ["../x.rego", false],
    ["/abs.rego", false],
    [".hidden.rego", false],
    ["a//b.rego", false],
  ])("%s → %s", (path, want) => {
    expect(isPolicyFile(path)).toBe(want)
  })
})
