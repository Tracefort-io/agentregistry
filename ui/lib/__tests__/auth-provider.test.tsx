import { render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const replace = vi.fn()
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }))

const signinRedirectCallback = vi.fn()
const signinRedirect = vi.fn()
const getUser = vi.fn()
vi.mock("oidc-client-ts", () => ({
  InMemoryWebStorage: class {},
  WebStorageStateStore: class {},
  UserManager: class {
    signinRedirectCallback = signinRedirectCallback
    signinRedirect = signinRedirect
    getUser = getUser
    events = { addUserLoaded: vi.fn(), addSilentRenewError: vi.fn(), unload: vi.fn() }
  },
}))

import { AuthProvider } from "../auth"

function serveAuthConfig() {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
    required: true, issuer: "http://idp/realms/r", clientId: "agentregistry-ui",
  }), { status: 200 })))
}

describe("AuthProvider", () => {
  beforeEach(() => {
    serveAuthConfig()
    replace.mockReset()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    window.history.replaceState(null, "", "/")
  })

  // The callback must navigate with the app router: changing the URL alone
  // leaves the callback page rendered, and a full reload would drop the
  // in-memory token.
  it("returns to the page the user started from after the callback", async () => {
    window.history.replaceState(null, "", "/auth/callback?code=c&state=s")
    signinRedirectCallback.mockResolvedValue({ access_token: "tok", expired: false, state: { returnTo: "/deployed" }, profile: {} })

    render(<AuthProvider><p>catalog</p></AuthProvider>)

    expect(await screen.findByText("catalog")).toBeInTheDocument()
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/deployed"))
  })

  it("never returns to another origin", async () => {
    window.history.replaceState(null, "", "/auth/callback?code=c2&state=s2")
    signinRedirectCallback.mockResolvedValue({ access_token: "tok", expired: false, state: { returnTo: "//evil.example" }, profile: {} })

    render(<AuthProvider><p>catalog</p></AuthProvider>)

    await waitFor(() => expect(replace).toHaveBeenCalledWith("/"))
  })

  // An unreachable identity provider must explain itself instead of leaving
  // the page on "Signing in…" with an unhandled rejection.
  it("explains when the sign-in service cannot be reached", async () => {
    window.history.replaceState(null, "", "/")
    getUser.mockResolvedValue(null)
    signinRedirect.mockRejectedValueOnce(new TypeError("NetworkError when attempting to fetch resource."))

    render(<AuthProvider><p>catalog</p></AuthProvider>)

    expect(await screen.findByText("Sign-in failed")).toBeInTheDocument()
    expect(screen.getByText(/Could not reach the sign-in service at http:\/\/idp\/realms\/r/)).toBeInTheDocument()
    expect(screen.queryByText("catalog")).not.toBeInTheDocument()
  })

  it("sends a user without a session to sign in and renders nothing", async () => {
    window.history.replaceState(null, "", "/deployed?x=1")
    getUser.mockResolvedValue(null)

    render(<AuthProvider><p>catalog</p></AuthProvider>)

    await waitFor(() => expect(signinRedirect).toHaveBeenCalledWith({ state: { returnTo: "/deployed?x=1" } }))
    expect(screen.queryByText("catalog")).not.toBeInTheDocument()
  })
})
