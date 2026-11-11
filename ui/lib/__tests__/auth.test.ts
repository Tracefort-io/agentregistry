import { describe, it, expect, vi } from "vitest"
import { createClient } from "@/lib/api/client"
import { CALLBACK_PATH, installAuthInterceptors, loadAuthConfig, safeReturnTo } from "../auth"

function jsonResponse(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  })
}

describe("loadAuthConfig", () => {
  it("returns the registry's sign-in settings", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(200, { required: true, issuer: "http://idp/realms/r", clientId: "agentregistry-ui", scopes: "openid" }),
    )
    const cfg = await loadAuthConfig("http://registry", fetchFn)
    expect(fetchFn).toHaveBeenCalledWith("http://registry/auth-config.json", { cache: "no-store" })
    expect(cfg).toEqual({ required: true, issuer: "http://idp/realms/r", clientId: "agentregistry-ui", scopes: "openid" })
  })

  it("requires no sign-in when the registry has no such endpoint", async () => {
    const cfg = await loadAuthConfig("http://registry", vi.fn().mockResolvedValue(jsonResponse(404)))
    expect(cfg).toEqual({ required: false })
  })

  it("treats anything but required: true as not required", async () => {
    const cfg = await loadAuthConfig("http://registry", vi.fn().mockResolvedValue(jsonResponse(200, { required: "yes" })))
    expect(cfg.required).toBe(false)
  })

  it("fails on other errors instead of skipping sign-in", async () => {
    await expect(loadAuthConfig("http://registry", vi.fn().mockResolvedValue(jsonResponse(503)))).rejects.toThrow("HTTP 503")
  })
})

describe("safeReturnTo", () => {
  it.each([
    ["/deployed?tab=x", "/deployed?tab=x"],
    ["/", "/"],
    ["https://evil.example/", "/"],
    ["//evil.example/path", "/"],
    ["/\\evil.example", "/"],
    ["deployed", "/"],
    [undefined, "/"],
    [42, "/"],
    [`${CALLBACK_PATH}?code=abc`, "/"],
  ])("%s -> %s", (input, want) => {
    expect(safeReturnTo(input)).toBe(want)
  })
})

describe("installAuthInterceptors", () => {
  it("adds the bearer token, reports 401 and can be removed", async () => {
    const seen: (string | null)[] = []
    const fetchFn = vi.fn(async (request: Request) => {
      seen.push(request.headers.get("Authorization"))
      return jsonResponse(request.url.endsWith("/denied") ? 401 : 200, {})
    })
    const api = createClient({ baseUrl: "http://registry", fetch: fetchFn as unknown as typeof fetch })
    let token: string | undefined = "tok-1"
    const onUnauthorized = vi.fn()

    const remove = installAuthInterceptors(api, () => token, onUnauthorized)
    await api.get({ url: "/v0/agents" })
    token = "tok-2"
    await api.get({ url: "/v0/denied" })

    expect(seen).toEqual(["Bearer tok-1", "Bearer tok-2"])
    expect(onUnauthorized).toHaveBeenCalledTimes(1)

    remove()
    await api.get({ url: "/v0/denied" })
    expect(seen[2]).toBeNull()
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  it("sends no header without a token", async () => {
    const fetchFn = vi.fn(async (request: Request) => {
      expect(request.headers.has("Authorization")).toBe(false)
      return jsonResponse(200, {})
    })
    const api = createClient({ baseUrl: "http://registry", fetch: fetchFn as unknown as typeof fetch })
    installAuthInterceptors(api, () => undefined, vi.fn())
    await api.get({ url: "/v0/agents" })
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })
})
