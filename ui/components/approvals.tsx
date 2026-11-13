"use client"

import { useEffect, useState } from "react"
import { toast } from "sonner"
import { RefreshCw } from "lucide-react"
import { client } from "@/lib/admin-api"
import {
  ApprovalRequest, ApprovalReview, cancelRequest, changeLabel, decide, fetchMyRequests, fetchReviews, isOpen,
} from "@/lib/approvals"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"

// Held changes move on asynchronously; refresh this often.
const REFRESH_MS = 10_000

const statusClass: Partial<Record<ApprovalRequest["status"], string>> = {
  pending: "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30",
  approved: "bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-500/30",
  applying: "bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-500/30",
  applied: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
  denied: "bg-destructive/10 text-destructive border-destructive/30",
  failed: "bg-destructive/10 text-destructive border-destructive/30",
}

function when(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

// Approvals shows the user's held changes and, for approvers, the changes
// awaiting their decision. Which changes need approval and who may approve
// them is the authorization policy's decision.
export function Approvals() {
  const [reload, setReload] = useState(0)
  const [mine, setMine] = useState<ApprovalRequest[]>([])
  const [mineError, setMineError] = useState("")
  const [reviews, setReviews] = useState<ApprovalReview[]>([])
  const [reviewError, setReviewError] = useState("")
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<ApprovalReview | null>(null)
  const [comment, setComment] = useState("")
  const [deciding, setDeciding] = useState(false)
  const [tab, setTab] = useState("mine")

  useEffect(() => {
    let cancelled = false
    Promise.all([fetchMyRequests(client), fetchReviews(client)]).then(([m, r]) => {
      if (cancelled) return
      setMine(m.items)
      setMineError(m.error)
      setReviews(r.items)
      setReviewError(r.error)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [reload])

  useEffect(() => {
    const t = setInterval(() => setReload((n) => n + 1), REFRESH_MS)
    return () => clearInterval(t)
  }, [])

  const withdraw = async (r: ApprovalRequest) => {
    const err = await cancelRequest(client, r.id)
    if (err) toast.error(err)
    else toast.success(`Withdrew ${changeLabel(r)}`)
    setReload((n) => n + 1)
  }

  const submit = async (decision: "approve" | "deny") => {
    if (!selected) return
    setDeciding(true)
    const err = await decide(client, selected.task.id, decision, comment)
    setDeciding(false)
    if (err) {
      toast.error(err)
      return
    }
    toast.success(decision === "approve" ? "Approved. The registry applies the change now." : "Denied.")
    setSelected(null)
    setComment("")
    setReload((n) => n + 1)
  }

  return (
    <main className="bg-background">
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between border-b pt-4 pb-3">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Approvals</h1>
            <p className="text-sm text-muted-foreground">
              Changes that need approval are held here and applied once approved.
            </p>
          </div>
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setReload((n) => n + 1)} title="Refresh">
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </div>

        <Tabs value={tab} onValueChange={setTab} className="pt-3">
          <TabsList>
            <TabsTrigger value="mine">My requests</TabsTrigger>
            <TabsTrigger value="review">To review{reviews.length > 0 ? ` (${reviews.length})` : ""}</TabsTrigger>
          </TabsList>

          <TabsContent value="mine">
            {loading ? (
              <p className="py-10 text-sm text-muted-foreground">Loading…</p>
            ) : mineError ? (
              <p className="py-10 text-sm text-destructive">{mineError}</p>
            ) : mine.length === 0 ? (
              <p className="py-16 text-center text-base font-medium">No requests</p>
            ) : (
              <div className="divide-y">
                {mine.map((r) => (
                  <div key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2 py-3 text-sm">
                    <span className="w-44 shrink-0 tabular-nums text-muted-foreground">{when(r.createdAt)}</span>
                    <span className="min-w-0 flex-1 truncate font-medium">{changeLabel(r)}</span>
                    <Badge variant="outline" className={statusClass[r.status] ?? ""}>{r.status}</Badge>
                    {r.detail && <span className="max-w-sm truncate text-muted-foreground" title={r.detail}>{r.detail}</span>}
                    {r.status === "pending" && (
                      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => void withdraw(r)}>
                        Withdraw
                      </Button>
                    )}
                    {isOpen(r.status) && r.status !== "pending" && <span className="text-xs text-muted-foreground">applying…</span>}
                  </div>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="review">
            {loading ? (
              <p className="py-10 text-sm text-muted-foreground">Loading…</p>
            ) : reviewError ? (
              <p className="py-10 text-sm text-destructive">{reviewError}</p>
            ) : reviews.length === 0 ? (
              <p className="py-16 text-center text-base font-medium">Nothing awaiting your approval</p>
            ) : (
              <div className="divide-y">
                {reviews.map((rv) => (
                  <div
                    key={rv.task.id}
                    className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 rounded-md px-2 py-3 text-sm hover:bg-muted/40"
                    onClick={() => setSelected(rv)}
                  >
                    <span className="min-w-0 flex-1 truncate font-medium">
                      {rv.change ? changeLabel(rv.change) : rv.task.display?.title ?? rv.task.id}
                    </span>
                    <span className="text-muted-foreground">
                      by {rv.change?.requesterUsername || rv.change?.requesterSubject || rv.task.request?.subject?.id || "unknown"}
                    </span>
                    {rv.change && <span className="tabular-nums text-muted-foreground">{when(rv.change.createdAt)}</span>}
                    <Button size="sm" className="h-7 text-xs">Review</Button>
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>

      <Dialog open={selected !== null} onOpenChange={(open) => !open && !deciding && setSelected(null)}>
        <DialogContent className="max-w-2xl" onClose={() => !deciding && setSelected(null)}>
          <DialogHeader>
            <DialogTitle>{selected?.change ? changeLabel(selected.change) : selected?.task.display?.title}</DialogTitle>
            <DialogDescription>
              Requested by {selected?.change?.requesterUsername || selected?.change?.requesterSubject || "unknown"}
              {selected?.change ? ` on ${when(selected.change.createdAt)}` : ""}. Approving applies exactly this document.
            </DialogDescription>
          </DialogHeader>
          <pre className="max-h-[45vh] overflow-auto rounded-md bg-muted p-3 text-xs">
            {selected?.change?.document ? JSON.stringify(selected.change.document, null, 2) : "The document is not available."}
          </pre>
          <Textarea placeholder="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} rows={2} />
          <DialogFooter>
            <Button variant="outline" onClick={() => void submit("deny")} disabled={deciding}>Deny</Button>
            <Button onClick={() => void submit("approve")} disabled={deciding}>Approve</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  )
}
