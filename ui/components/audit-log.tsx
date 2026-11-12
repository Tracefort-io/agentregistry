"use client"

import { useEffect, useState } from "react"
import { RefreshCw } from "lucide-react"
import { client } from "@/lib/admin-api"
import { actorLabel, AuditEvent, AuditFilters, fetchAuditPage, NO_FILTERS, resourceLabel } from "@/lib/audit"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"

const selectClass =
  "h-8 rounded-md border border-input bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"

const outcomeClass: Record<AuditEvent["outcome"], string> = {
  success: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
  denied: "bg-destructive/10 text-destructive border-destructive/30",
  failure: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30",
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

// AuditLog shows who applied or deleted what, and which reads were refused,
// newest first. The registry serves it to registry admins only.
export function AuditLog() {
  const [draft, setDraft] = useState<AuditFilters>(NO_FILTERS)
  const [filters, setFilters] = useState<AuditFilters>(NO_FILTERS)
  const [reload, setReload] = useState(0)
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [nextCursor, setNextCursor] = useState("")
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState("")
  const [selected, setSelected] = useState<AuditEvent | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchAuditPage(client, filters).then((page) => {
      if (cancelled) return
      setEvents(page.events)
      setNextCursor(page.nextCursor)
      setError(page.error)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [filters, reload])

  const search = (next: AuditFilters) => {
    setLoading(true)
    setFilters(next)
    setReload((n) => n + 1)
  }

  const loadMore = async () => {
    setLoadingMore(true)
    const page = await fetchAuditPage(client, filters, nextCursor)
    setLoadingMore(false)
    if (page.error) {
      setError(page.error)
      return
    }
    setEvents((prev) => [...prev, ...page.events])
    setNextCursor(page.nextCursor)
  }

  const field = (key: keyof AuditFilters) => ({
    value: draft[key],
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setDraft({ ...draft, [key]: e.target.value }),
  })

  return (
    <main className="bg-background">
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between border-b pt-4 pb-3">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Audit log</h1>
            <p className="text-sm text-muted-foreground">
              Who applied or deleted what, and which reads were refused. Newest first.
            </p>
          </div>
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => search(filters)} title="Refresh">
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </div>

        <form
          className="flex flex-wrap items-center gap-2 py-3"
          onSubmit={(e) => {
            e.preventDefault()
            search(draft)
          }}
        >
          <Input className="h-8 w-40" placeholder="User or subject" aria-label="User or subject" {...field("actor")} />
          <select className={selectClass} aria-label="Action" {...field("action")}>
            <option value="">Any action</option>
            <option value="apply">apply</option>
            <option value="delete">delete</option>
            <option value="read">read</option>
            <option value="list">list</option>
          </select>
          <select className={selectClass} aria-label="Outcome" {...field("outcome")}>
            <option value="">Any outcome</option>
            <option value="success">success</option>
            <option value="denied">denied</option>
            <option value="failure">failure</option>
          </select>
          <Input className="h-8 w-32" placeholder="Kind" aria-label="Kind" {...field("kind")} />
          <Input className="h-8 w-32" placeholder="Namespace" aria-label="Namespace" {...field("namespace")} />
          <Input className="h-8 w-40" placeholder="Name" aria-label="Name" {...field("name")} />
          <Button type="submit" size="sm" className="h-8">Search</Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8"
            onClick={() => {
              setDraft(NO_FILTERS)
              search(NO_FILTERS)
            }}
          >
            Clear
          </Button>
        </form>

        {loading ? (
          <p className="py-10 text-sm text-muted-foreground">Loading…</p>
        ) : error && events.length === 0 ? (
          <p className="py-10 text-sm text-destructive">{error}</p>
        ) : events.length === 0 ? (
          <p className="py-16 text-center text-base font-medium">No audit events</p>
        ) : (
          <>
            <div className="divide-y border-t">
              {events.map((e) => (
                <div
                  key={e.id}
                  className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 rounded-md px-2 py-2.5 text-sm hover:bg-muted/40"
                  onClick={() => setSelected(e)}
                >
                  <span className="w-44 shrink-0 tabular-nums text-muted-foreground">{formatTime(e.time)}</span>
                  <span className="w-36 shrink-0 truncate font-medium" title={e.actor.subject}>{actorLabel(e.actor)}</span>
                  <Badge variant="secondary" className="w-14 justify-center">{e.action}</Badge>
                  <Badge variant="outline" className={`w-16 justify-center ${outcomeClass[e.outcome] ?? ""}`}>{e.outcome}</Badge>
                  <span className="shrink-0 text-muted-foreground">{e.resource.kind}</span>
                  <span className="min-w-0 flex-1 truncate">{resourceLabel(e.resource)}</span>
                  {e.detail && <span className="max-w-xs truncate text-muted-foreground" title={e.detail}>{e.detail}</span>}
                </div>
              ))}
            </div>
            {error && <p className="py-3 text-sm text-destructive">{error}</p>}
            {nextCursor && (
              <div className="py-4 text-center">
                <Button variant="outline" size="sm" onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? "Loading…" : "Load more"}
                </Button>
              </div>
            )}
          </>
        )}
      </div>

      <Dialog open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-w-2xl" onClose={() => setSelected(null)}>
          <DialogHeader>
            <DialogTitle>
              {selected ? `${actorLabel(selected.actor)} ${selected.action} ${selected.resource.kind} ${resourceLabel(selected.resource)}` : ""}
            </DialogTitle>
            <DialogDescription>{selected ? `${formatTime(selected.time)} · ${selected.outcome}` : ""}</DialogDescription>
          </DialogHeader>
          <pre className="max-h-[60vh] overflow-auto rounded-md bg-muted p-3 text-xs">
            {selected ? JSON.stringify(selected, null, 2) : ""}
          </pre>
        </DialogContent>
      </Dialog>
    </main>
  )
}
