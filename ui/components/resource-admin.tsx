"use client"

import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Plus, RefreshCw, Trash2 } from "lucide-react"
import { applyBatch, client, deleteBatch } from "@/lib/admin-api"
import { useCan } from "@/lib/permissions"
import { AdminItem, ApplyResult, deleteDocument, failedResults, RESOURCE_KINDS, ResourceKind, ResourceKindName } from "@/lib/resource-kinds"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Textarea } from "@/components/ui/textarea"
import { DeleteConfirmationDialog } from "@/components/delete-confirmation-dialog"

const LIST_LIMIT = 200

function itemLabel(item: AdminItem): string {
  const ns = item.metadata.namespace || "default"
  return item.metadata.tag ? `${ns}/${item.metadata.name}@${item.metadata.tag}` : `${ns}/${item.metadata.name}`
}

async function fetchItems(kind: ResourceKind): Promise<{ items: AdminItem[]; error: string }> {
  const { data, response } = await client.get<{ 200: { items?: AdminItem[] } }, unknown, false>({
    url: `/v0/${kind.plural}`,
    query: { namespace: "all", limit: LIST_LIMIT },
  })
  if (response?.status === 403) {
    return { items: [], error: `You don't have permission to view ${kind.title.toLowerCase()}.` }
  }
  if (!response?.ok) {
    return { items: [], error: `Could not load ${kind.title.toLowerCase()} (HTTP ${response?.status ?? "error"}).` }
  }
  return { items: data?.items ?? [], error: "" }
}

function yamlBody(text: string): Blob {
  return new Blob([text], { type: "application/yaml" })
}

// ResourceAdmin lists one platform kind across all namespaces and, when the
// signed-in user may, lets them add resources from YAML and delete them. It
// takes the kind's name: pages are server components and cannot pass the
// kind's settings, which include functions.
export function ResourceAdmin({ kindName }: { kindName: ResourceKindName }) {
  const kind = RESOURCE_KINDS[kindName]
  const can = useCan()
  const canAdd = can(kind.kind, "apply")
  const canDelete = can(kind.kind, "delete")

  const [items, setItems] = useState<AdminItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [selected, setSelected] = useState<AdminItem | null>(null)
  const [toDelete, setToDelete] = useState<AdminItem | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [adding, setAdding] = useState(false)
  const [yaml, setYaml] = useState(kind.template)
  const [applying, setApplying] = useState(false)
  const [applyErrors, setApplyErrors] = useState<ApplyResult[]>([])

  // Bumping reloads triggers a fetch; state is set only once it completes.
  const [reloads, setReloads] = useState(0)
  const load = useCallback(() => {
    setLoading(true)
    setReloads((n) => n + 1)
  }, [])

  useEffect(() => {
    let cancelled = false
    fetchItems(kind).then((result) => {
      if (cancelled) return
      setItems(result.items)
      setError(result.error)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [kind, reloads])

  async function confirmDelete() {
    if (!toDelete) return
    setDeleting(true)
    const { data, response } = await deleteBatch({ body: yamlBody(deleteDocument(kind, toDelete)) })
    const failed = failedResults(data?.results as ApplyResult[] | undefined)
    setDeleting(false)
    if (!response?.ok || failed.length > 0) {
      toast.error(failed[0]?.error || `Could not delete ${itemLabel(toDelete)} (HTTP ${response?.status ?? "error"}).`)
      return
    }
    toast.success(`Deleted ${itemLabel(toDelete)}`)
    setToDelete(null)
    load()
  }

  async function applyYaml() {
    setApplying(true)
    setApplyErrors([])
    const { data, response } = await applyBatch({ body: yamlBody(yaml) })
    setApplying(false)
    const results = (data?.results ?? []) as ApplyResult[]
    const failed = failedResults(results)
    if (!response?.ok) {
      setApplyErrors([{ name: kind.kind, status: "failed", error: `HTTP ${response?.status ?? "error"}` }])
      return
    }
    if (failed.length > 0) {
      setApplyErrors(failed)
      return
    }
    toast.success(`Applied ${results.map((r) => `${r.kind ?? kind.kind} ${r.name}: ${r.status}`).join(", ")}`)
    setAdding(false)
    setYaml(kind.template)
    load()
  }

  return (
    <main className="bg-background">
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between border-b pt-4 pb-3">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">{kind.title}</h1>
            <p className="text-sm text-muted-foreground">{kind.description}</p>
          </div>
          <div className="flex items-center gap-2">
            {canAdd && (
              <Button size="sm" className="gap-1.5 h-8" onClick={() => setAdding(true)}>
                <Plus className="h-3.5 w-3.5" />
                Add
              </Button>
            )}
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={load} title="Refresh">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        {loading ? (
          <p className="py-10 text-sm text-muted-foreground">Loading…</p>
        ) : error ? (
          <p className="py-10 text-sm text-destructive">{error}</p>
        ) : items.length === 0 ? (
          <div className="py-16 text-center">
            <p className="text-base font-medium">No {kind.title.toLowerCase()}</p>
            {canAdd && (
              <Button variant="outline" size="sm" className="mt-4 gap-1.5" onClick={() => setAdding(true)}>
                <Plus className="h-3.5 w-3.5" /> Add {kind.kind}
              </Button>
            )}
          </div>
        ) : (
          <div className="divide-y">
            {items.map((item) => (
              <div
                key={itemLabel(item)}
                className="group flex items-center gap-3 py-3 cursor-pointer hover:bg-muted/40 px-2 rounded-md"
                onClick={() => setSelected(item)}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium truncate">{item.metadata.name}</span>
                    <Badge variant="outline">{item.metadata.namespace || "default"}</Badge>
                    {item.metadata.tag && <Badge variant="secondary">{item.metadata.tag}</Badge>}
                  </div>
                  <p className="text-sm text-muted-foreground truncate">{kind.summary(item)}</p>
                </div>
                {canDelete && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 gap-1 text-xs text-destructive hover:text-destructive hover:bg-destructive/10 opacity-0 group-hover:opacity-100"
                    onClick={(e) => {
                      e.stopPropagation()
                      setToDelete(item)
                    }}
                  >
                    <Trash2 className="h-3 w-3" />
                    Delete
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <Dialog open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-w-2xl" onClose={() => setSelected(null)}>
          <DialogHeader>
            <DialogTitle>{selected ? itemLabel(selected) : ""}</DialogTitle>
            <DialogDescription>{kind.kind}</DialogDescription>
          </DialogHeader>
          <pre className="max-h-[60vh] overflow-auto rounded-md bg-muted p-3 text-xs">
            {selected ? JSON.stringify(selected, null, 2) : ""}
          </pre>
        </DialogContent>
      </Dialog>

      <Dialog open={adding} onOpenChange={(open) => !applying && setAdding(open)}>
        <DialogContent className="max-w-2xl" onClose={() => !applying && setAdding(false)}>
          <DialogHeader>
            <DialogTitle>Add {kind.kind}</DialogTitle>
            <DialogDescription>YAML in the arctl apply format. Several documents may be separated by ---.</DialogDescription>
          </DialogHeader>
          <Textarea
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
            className="min-h-[300px] font-mono text-xs"
            spellCheck={false}
            aria-label={`${kind.kind} YAML`}
          />
          {applyErrors.length > 0 && (
            <ul className="space-y-1 text-sm text-destructive">
              {applyErrors.map((r, i) => (
                <li key={i}>{`${r.kind ?? kind.kind} ${r.name}: ${r.error ?? r.status}`}</li>
              ))}
            </ul>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setAdding(false)} disabled={applying}>
              Cancel
            </Button>
            <Button onClick={() => void applyYaml()} disabled={applying}>
              {applying ? "Applying…" : "Apply"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <DeleteConfirmationDialog
        open={toDelete !== null}
        onOpenChange={(open) => !open && setToDelete(null)}
        onConfirm={() => void confirmDelete()}
        title={`Delete ${kind.kind}`}
        itemName={toDelete ? itemLabel(toDelete) : ""}
        isDeleting={deleting}
      />
    </main>
  )
}
