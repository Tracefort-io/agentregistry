"use client"

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react"
import { useRouter } from "next/navigation"
import { InMemoryWebStorage, User, UserManager, WebStorageStateStore } from "oidc-client-ts"
import { client } from "@/lib/admin-api"

// The browser returns here from the identity provider (app/auth/callback).
export const CALLBACK_PATH = "/auth/callback"

// AuthConfig is served by the registry at /auth-config.json.
export interface AuthConfig {
  required: boolean
  issuer?: string
  clientId?: string
  scopes?: string
}

// loadAuthConfig reads the registry's sign-in settings. A registry that
// predates the endpoint (404) requires no sign-in.
export async function loadAuthConfig(baseUrl: string, fetchFn: typeof fetch = fetch): Promise<AuthConfig> {
  const res = await fetchFn(`${baseUrl}/auth-config.json`, { cache: "no-store" })
  if (res.status === 404) return { required: false }
  if (!res.ok) throw new Error(`Could not load sign-in settings (HTTP ${res.status})`)
  const body = (await res.json()) as AuthConfig
  return { ...body, required: body.required === true }
}

// safeReturnTo keeps a post-sign-in redirect on this site: only a path that
// starts with a single "/" is accepted, so the state cannot send the user to
// another origin.
export function safeReturnTo(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) {
    return "/"
  }
  return value.startsWith(CALLBACK_PATH) ? "/" : value
}

// createUserManager signs users in with the authorization code flow and PKCE.
// Tokens stay in memory, out of reach of anything reading browser storage;
// after a reload the identity provider's session signs the user straight back
// in. Only the short-lived PKCE state uses sessionStorage, because it must
// survive the redirect.
export function createUserManager(config: AuthConfig, origin: string): UserManager {
  return new UserManager({
    authority: config.issuer!,
    client_id: config.clientId!,
    redirect_uri: `${origin}${CALLBACK_PATH}`,
    post_logout_redirect_uri: `${origin}/`,
    response_type: "code",
    scope: config.scopes || "openid profile email",
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    automaticSilentRenew: true,
  })
}

type Interceptable = Pick<typeof client, "interceptors">

// installAuthInterceptors adds the bearer token to every API request and
// calls onUnauthorized when the registry answers 401. It returns a function
// that removes both interceptors.
export function installAuthInterceptors(
  api: Interceptable,
  getToken: () => string | undefined,
  onUnauthorized: () => void,
): () => void {
  const requestId = api.interceptors.request.use((request) => {
    const token = getToken()
    if (token) request.headers.set("Authorization", `Bearer ${token}`)
    return request
  })
  const responseId = api.interceptors.response.use((response) => {
    if (response.status === 401) onUnauthorized()
    return response
  })
  return () => {
    api.interceptors.request.eject(requestId)
    api.interceptors.response.eject(responseId)
  }
}

type AuthStatus = "loading" | "disabled" | "signed-in" | "error"

interface AuthContextValue {
  status: AuthStatus
  user: User | null
  signOut: () => void
}

const AuthContext = createContext<AuthContextValue>({ status: "disabled", user: null, signOut: () => {} })

// useAuth returns the signed-in user, or null when sign-in is not required.
export function useAuth(): AuthContextValue {
  return useContext(AuthContext)
}

function apiBaseUrl(): string {
  return client.getConfig().baseUrl || window.location.origin
}

// The authorization code in a callback URL can be exchanged only once, but
// React may run effects twice in development; share one exchange per URL.
let callbackExchange: { url: string; user: Promise<User> } | null = null

function completeSignIn(mgr: UserManager): Promise<User> {
  const url = window.location.href
  if (callbackExchange?.url !== url) {
    callbackExchange = { url, user: mgr.signinRedirectCallback(url) }
  }
  return callbackExchange.user
}

// AuthProvider signs the user in when the registry requires it and holds the
// page until then, so no API call is made without a token.
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading")
  const [user, setUser] = useState<User | null>(null)
  const [error, setError] = useState<string>("")
  const manager = useRef<UserManager | null>(null)
  // Read through a ref: sign-in must run once, not again whenever the
  // router object changes identity.
  const router = useRouter()
  const routerRef = useRef(router)
  useEffect(() => {
    routerRef.current = router
  }, [router])

  const issuer = useRef("")

  // signIn leaves for the identity provider. If it cannot be reached (it is
  // down, or its hostname does not resolve) the page says so instead of
  // waiting forever.
  const signIn = useCallback(() => {
    const returnTo = window.location.pathname + window.location.search
    manager.current?.signinRedirect({ state: { returnTo: safeReturnTo(returnTo) } }).catch((err: unknown) => {
      const reason = err instanceof Error ? err.message : String(err)
      setError(`Could not reach the sign-in service at ${issuer.current} (${reason}). Check that it is running and reachable from this browser.`)
      setStatus("error")
    })
  }, [])

  const signOut = useCallback(() => {
    void manager.current?.signoutRedirect()
  }, [])

  useEffect(() => {
    let cancelled = false
    let removeInterceptors: (() => void) | undefined
    let current: User | null = null
    // Where to go once signed in, when arriving at the callback.
    let returnTo: string | null = null

    async function start() {
      const config = await loadAuthConfig(apiBaseUrl())
      if (!config.required) {
        if (!cancelled) setStatus("disabled")
        return
      }
      if (!config.issuer || !config.clientId) {
        throw new Error("This registry requires sign-in, but no sign-in client is configured (AUTH_UI_ISSUER, AUTH_UI_CLIENT_ID).")
      }
      const mgr = createUserManager(config, window.location.origin)
      manager.current = mgr
      issuer.current = config.issuer

      if (window.location.pathname === CALLBACK_PATH) {
        current = await completeSignIn(mgr)
        const state = current.state as { returnTo?: unknown } | undefined
        returnTo = safeReturnTo(state?.returnTo)
      } else {
        current = await mgr.getUser()
        if (!current || current.expired) {
          signIn()
          return
        }
      }

      mgr.events.addUserLoaded((u) => {
        current = u
        setUser(u)
      })
      // A failed renewal (expired session) means signing in again.
      mgr.events.addSilentRenewError(() => signIn())
      removeInterceptors = installAuthInterceptors(client, () => current?.access_token, signIn)
      if (!cancelled) {
        setUser(current)
        setStatus("signed-in")
        // Navigate with the app router: it renders the page the user started
        // from. A full reload would drop the in-memory token.
        if (returnTo) routerRef.current.replace(returnTo)
      }
    }

    start().catch((err: unknown) => {
      if (cancelled) return
      setError(err instanceof Error ? err.message : String(err))
      setStatus("error")
    })
    return () => {
      cancelled = true
      removeInterceptors?.()
      manager.current?.events.unload()
    }
  }, [signIn])

  if (status === "loading") {
    return <AuthMessage title="Signing in…" />
  }
  if (status === "error") {
    return <AuthMessage title="Sign-in failed" detail={error} action={{ label: "Try again", onClick: () => window.location.assign("/") }} />
  }
  return <AuthContext.Provider value={{ status, user, signOut }}>{children}</AuthContext.Provider>
}

function AuthMessage({ title, detail, action }: { title: string; detail?: string; action?: { label: string; onClick: () => void } }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <div className="max-w-md text-center space-y-3">
        <p className="text-lg font-semibold text-foreground">{title}</p>
        {detail && <p className="text-sm text-muted-foreground">{detail}</p>}
        {action && (
          <button onClick={action.onClick} className="text-sm font-medium text-primary hover:underline">
            {action.label}
          </button>
        )}
      </div>
    </div>
  )
}
