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

// Permissions is what the UI knows the signed-in user may do.
export interface Permissions {
  can: Can
  // admin is true for registry admins, who may read the audit log.
  admin: boolean
}

const none: Permissions = { can: allowNothing, admin: false }

// loadPermissions asks the registry what the user may do. It hides every
// action when the answer is unavailable (the registry still refuses what is
// not allowed), and allows everything on a registry that predates /v0/me.
export async function loadPermissions(api: Pick<typeof client, "get">): Promise<Permissions> {
  const { data, response } = await api.get<{ 200: Me }, unknown, false>({
    url: "/v0/me",
    query: { namespace: PERMISSIONS_NAMESPACE },
  })
  if (response?.status === 404) return { can: allowEverything, admin: true }
  if (!response?.ok || !data || typeof data.permissions !== "object") return none
  return { can: canFrom(data), admin: data.admin === true }
}

// loadCan is loadPermissions without the admin flag.
export async function loadCan(api: Pick<typeof client, "get">): Promise<Can> {
  return (await loadPermissions(api)).can
}

const PermissionsContext = createContext<Permissions>(none)

// useCan returns whether the signed-in user may take an action on a kind.
// The answer is for showing actions only; every request is still authorized.
export function useCan(): Can {
  return useContext(PermissionsContext).can
}

// useIsAdmin returns whether the signed-in user is a registry admin. Like
// useCan, it only decides what to show.
export function useIsAdmin(): boolean {
  return useContext(PermissionsContext).admin
}

// PermissionsProvider loads the user's permissions after sign-in, and again
// when a different user signs in.
export function PermissionsProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth()
  const subject = user?.profile.sub
  const [permissions, setPermissions] = useState<Permissions>(none)

  useEffect(() => {
    let cancelled = false
    loadPermissions(client)
      .then((next) => {
        if (!cancelled) setPermissions(next)
      })
      .catch(() => {
        if (!cancelled) setPermissions(none)
      })
    return () => {
      cancelled = true
    }
  }, [subject])

  return <PermissionsContext.Provider value={permissions}>{children}</PermissionsContext.Provider>
}
