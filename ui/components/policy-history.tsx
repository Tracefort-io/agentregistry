"use client"

import { useEffect, useState } from "react"
import { toast } from "sonner"
import { ExternalLink } from "lucide-react"
import { client } from "@/lib/admin-api"
import { fetchDiff, fetchPending, fetchPolicy, fetchVersions, type Draft, type PolicyChange, type PolicyVersion, type PullRequest } from "@/lib/policies"
import { Button } from "@/components/ui/button"

function when(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

// PolicyHistory lists a policy's versions (one per merged change), shows
// what each changed, and the open pull requests that would change it.
export function PolicyHistory({ name, onRestore }: { name: string; onRestore: (files: Draft, version: string) => void }) {
  const [versions, setVersions] = useState<PolicyVersion[]>([])
  const [pending, setPending] = useState<PullRequest[]>([])
  const [error, setError] = useState("")
  const [selected, setSelected] = useState<string>("")
  const [diff, setDiff] = useState<PolicyChange[] | null>(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([fetchVersions(client, name), fetchPending(client, name)]).then(([v, p]) => {
      if (cancelled) return
      setVersions(v.ok ? v.value : [])
      setPending(p.ok ? p.value : [])
      setError(!v.ok ? v.error : !p.ok ? p.error : "")
    })
    return () => {
      cancelled = true
    }
  }, [name])

  // Compare a version with the one before it, or with nothing for v1.
  const show = async (v: PolicyVersion, i: number) => {
    setSelected(v.version)
    setDiff(null)
    const previous = versions[i + 1]
    if (!previous) {
      const r = await fetchPolicy(client, name, v.version)
      if (!r.ok) return void toast.error(r.error)
      setDiff(r.value.files.map((f) => ({ path: f.path, new: f.content })))
      return
    }
    const r = await fetchDiff(client, name, previous.version, v.version)
    if (!r.ok) return void toast.error(r.error)
    setDiff(r.value)
  }

  const restore = async (v: PolicyVersion) => {
    const r = await fetchPolicy(client, name, v.version)
    if (!r.ok) return void toast.error(r.error)
    onRestore(Object.fromEntries(r.value.files.map((f) => [f.path, f.content])), v.version)
  }

  return (
    <div className="grid gap-4 py-2 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
      <section>
        {error && <p className="pb-2 text-sm text-destructive">{error}</p>}
        <h2 className="pb-1 text-sm font-semibold">Pending changes</h2>
        {pending.length === 0 ? (
          <p className="pb-4 text-sm text-muted-foreground">No open pull requests change this policy.</p>
        ) : (
          <ul className="divide-y pb-4 text-sm">
            {pending.map((pr) => (
              <li key={pr.number} className="flex items-center gap-2 py-2">
                <a className="min-w-0 flex-1 truncate font-medium hover:underline" href={pr.url} target="_blank" rel="noreferrer">
                  #{pr.number} {pr.title}
                </a>
                <span className="text-muted-foreground">{pr.author}</span>
                <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
              </li>
            ))}
          </ul>
        )}
        <h2 className="pb-1 text-sm font-semibold">Versions</h2>
        {versions.length === 0 ? (
          <p className="text-sm text-muted-foreground">No versions yet: one is tagged each time a change is merged.</p>
        ) : (
          <ul className="divide-y text-sm">
            {versions.map((v, i) => (
              <li key={v.tag} className={`flex flex-wrap items-center gap-x-2 rounded px-2 py-2 ${selected === v.version ? "bg-primary/10" : ""}`}>
                <button className="min-w-0 flex-1 text-left" onClick={() => void show(v, i)}>
                  <span className="font-medium">{v.version}</span>{" "}
                  <span className="text-muted-foreground">{v.message.split("\n")[0]}</span>
                  <span className="block text-xs text-muted-foreground">{v.author}, {when(v.date)}, {v.commit.slice(0, 8)}</span>
                </button>
                {i > 0 && (
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => void restore(v)} title="Load this version into the editor">
                    Restore
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        {selected && (
          <>
            <h2 className="pb-1 text-sm font-semibold">What {selected} changed</h2>
            {diff === null ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : diff.length === 0 ? (
              <p className="text-sm text-muted-foreground">No file changes in this policy.</p>
            ) : (
              <div className="space-y-3">
                {diff.map((c) => (
                  <div key={c.path} className="rounded-md border">
                    <div className="bg-muted px-2 py-1 font-mono text-xs">
                      {c.old === undefined ? "added" : c.new === undefined ? "deleted" : "changed"} {c.path}
                    </div>
                    <div className="grid grid-cols-2 divide-x text-xs">
                      <pre className="max-h-80 overflow-auto whitespace-pre-wrap p-2 font-mono text-muted-foreground">{c.old ?? ""}</pre>
                      <pre className="max-h-80 overflow-auto whitespace-pre-wrap p-2 font-mono">{c.new ?? ""}</pre>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </section>
    </div>
  )
}
