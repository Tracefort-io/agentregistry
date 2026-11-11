"use client"

import { createContext, useContext, useEffect, useState } from "react"
import { client } from "@/lib/admin-api"
import { useAuth } from "@/lib/auth"

// New resources are created in this namespace, so the UI asks about it.
export const PERMISSIONS_NAMESPACE = "default"

export type Action = "read" | "list" | "apply" | "delete" | "deploy"

// Me is the part of GET /v0/me the UI uses.
export interface Me {
  enforced: boolean
  admin: boolean
  permissions: Record<string, string[]>
}

// Can answers whether the signed-in user may take an action on a kind.
export type Can = (kind: string, action: Action) => boolean

const allowNothing: Can = () => false
const allowEverything: Can = () => true

// canFrom turns a /v0/me answer into a Can.
export function canFrom(me: Me): Can {
  return (kind, action) => me.permissions[kind]?.includes(action) ?? false
}

// loadCan asks the registry what the user may do. It hides every action when
// the answer is unavailable (the registry still refuses what is not allowed),
// and allows every action on a registry that predates /v0/me.
export async function loadCan(api: Pick<typeof client, "get">): Promise<Can> {
  const { data, response } = await api.get<{ 200: Me }, unknown, false>({
    url: "/v0/me",
    query: { namespace: PERMISSIONS_NAMESPACE },
  })
  if (response?.status === 404) return allowEverything
  if (!response?.ok || !data || typeof data.permissions !== "object") return allowNothing
  return canFrom(data)
}

const PermissionsContext = createContext<Can>(allowNothing)

// useCan returns whether the signed-in user may take an action on a kind.
// The answer is for showing actions only; every request is still authorized.
export function useCan(): Can {
  return useContext(PermissionsContext)
}

// PermissionsProvider loads the user's permissions after sign-in, and again
// when a different user signs in.
export function PermissionsProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth()
  const subject = user?.profile.sub
  const [can, setCan] = useState<Can>(() => allowNothing)

  useEffect(() => {
    let cancelled = false
    loadCan(client)
      .then((next) => {
        if (!cancelled) setCan(() => next)
      })
      .catch(() => {
        if (!cancelled) setCan(() => allowNothing)
      })
    return () => {
      cancelled = true
    }
  }, [subject])

  return <PermissionsContext.Provider value={can}>{children}</PermissionsContext.Provider>
}
