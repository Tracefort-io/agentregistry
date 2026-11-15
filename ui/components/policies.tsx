"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"
import { useEffect, useState } from "react"
import { Plus, RefreshCw } from "lucide-react"
import { client } from "@/lib/admin-api"
import { fetchPolicies, type PolicySummary } from "@/lib/policies"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"

const NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/

export const editorHref = (name: string) => `/policies/edit?policy=${encodeURIComponent(name)}`

// Policies lists the Rego policies in the policy repository, read live from
// the branch OPAL tracks.
export function Policies() {
  const router = useRouter()
  const [reload, setReload] = useState(0)
  const [policies, setPolicies] = useState<PolicySummary[]>([])
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState("")

  useEffect(() => {
    let cancelled = false
    fetchPolicies(client).then((r) => {
      if (cancelled) return
      setPolicies(r.ok ? r.value : [])
      setError(r.ok ? "" : r.error)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [reload])

  const nameError = newName && !NAME.test(newName)
    ? "Use lowercase letters, digits, '-' or '_', starting with a letter or digit."
    : policies.some((p) => p.name === newName) ? "A policy with this name exists." : ""

  return (
    <main className="bg-background">
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between gap-3 border-b pt-4 pb-3">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Policies</h1>
            <p className="text-sm text-muted-foreground">
              Rego policies and data from the policy repository. Changes are published as pull requests and go live when merged.
            </p>
          </div>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setReload((n) => n + 1)} title="Refresh">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
            <Button size="sm" className="h-8" onClick={() => setCreating(true)}>
              <Plus className="mr-1 h-3.5 w-3.5" /> New policy
            </Button>
          </div>
        </div>

        {loading ? (
          <p className="py-10 text-sm text-muted-foreground">Loading…</p>
        ) : error ? (
          <p className="py-10 text-sm text-destructive">{error}</p>
        ) : policies.length === 0 ? (
          <p className="py-16 text-center text-base font-medium">No policies you may read</p>
        ) : (
          <div className="divide-y">
            {policies.map((p) => (
              <Link
                key={p.name}
                href={editorHref(p.name)}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md px-2 py-3 text-sm hover:bg-muted/40"
              >
                <span className="w-48 shrink-0 truncate font-medium">{p.name}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={p.packages.join(", ")}>
                  {p.packages.join(", ") || "no packages"}
                </span>
                {p.dataPaths.length > 0 && (
                  <span className="truncate font-mono text-xs text-muted-foreground" title={p.dataPaths.join(", ")}>
                    {p.dataPaths.join(", ")}
                  </span>
                )}
                <span className="tabular-nums text-muted-foreground">{p.files} files</span>
                <Badge variant="outline">{p.latestVersion ?? "unversioned"}</Badge>
              </Link>
            ))}
          </div>
        )}
      </div>

      <Dialog open={creating} onOpenChange={setCreating}>
        <DialogContent className="max-w-md" onClose={() => setCreating(false)}>
          <DialogHeader>
            <DialogTitle>New policy</DialogTitle>
            <DialogDescription>
              The name is the policy&apos;s directory in the repository. It is created when you publish it.
            </DialogDescription>
          </DialogHeader>
          <Input aria-label="Policy name" placeholder="for example: authzen" value={newName} onChange={(e) => setNewName(e.target.value.trim())} />
          {nameError && <p className="text-xs text-destructive">{nameError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreating(false)}>Cancel</Button>
            <Button disabled={!newName || !!nameError} onClick={() => router.push(editorHref(newName))}>Open editor</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  )
}
