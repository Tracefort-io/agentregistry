"use client"

import Link from "next/link"
import { useCallback, useEffect, useMemo, useState } from "react"
import { useSearchParams } from "next/navigation"
import { toast } from "sonner"
import { ArrowLeft, CheckCircle2, FilePlus, Play, Send, TestTube2, Wand2, X } from "lucide-react"
import { client } from "@/lib/admin-api"
import {
  changedFiles, checkDraft, evaluateDraft, fetchPolicy, fetchStatus, formatFile, parseJSON, publishDraft,
  sampleInput, testDraft, type Draft, type Policy, type PolicyStatus, type Problem, type PublishResult,
} from "@/lib/policies"
import { CodeEditor } from "@/components/code-editor"
import { DeleteConfirmationDialog } from "@/components/delete-confirmation-dialog"
import { PolicyAddFileDialog } from "@/components/policy-add-file-dialog"
import { PolicyHistory } from "@/components/policy-history"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"

type Busy = "" | "format" | "check" | "evaluate" | "test" | "publish"

const panelTitle = "flex items-center justify-between bg-muted px-2 py-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground"

// newPolicyFile starts a policy that doesn't exist yet.
function newPolicyFile(name: string): Draft {
  return { [`${name}.rego`]: `package ${name.replace(/-/g, "_")}\n\ndefault allow := false\n` }
}

function languageOf(path: string): "rego" | "json" | "text" {
  if (path.endsWith(".rego")) return "rego"
  if (path.endsWith(".json")) return "json"
  return "text"
}

// PolicyEditorPage reads the policy name from ?policy=.
export function PolicyEditorPage() {
  const name = useSearchParams().get("policy") ?? ""
  if (!name) {
    return <p className="container mx-auto px-6 py-10 text-sm text-destructive">No policy selected. <Link className="underline" href="/policies">Back to policies</Link></p>
  }
  return <PolicyEditor name={name} />
}

// PolicyEditor edits one policy as a draft, runs it in the registry, and
// publishes the draft as a pull request.
export function PolicyEditor({ name }: { name: string }) {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [loadError, setLoadError] = useState("")
  const [draft, setDraft] = useState<Draft>({})
  const [active, setActive] = useState("")
  const [status, setStatus] = useState<PolicyStatus | null>(null)
  const [query, setQuery] = useState("")
  const [inputText, setInputText] = useState(JSON.stringify(sampleInput, null, 2))
  const [dataText, setDataText] = useState("{}")
  const [output, setOutput] = useState("")
  const [problems, setProblems] = useState<Problem[]>([])
  const [busy, setBusy] = useState<Busy>("")
  const [tab, setTab] = useState("editor")
  const [publishing, setPublishing] = useState(false)
  const [message, setMessage] = useState("")
  const [published, setPublished] = useState<PublishResult | null>(null)
  const [reload, setReload] = useState(0)
  const [addingFile, setAddingFile] = useState(false)
  const [fileToRemove, setFileToRemove] = useState<string | null>(null)

  const load = useCallback((p: Policy, files?: Draft) => {
    const d: Draft = files ?? (p.files.length > 0 ? Object.fromEntries(p.files.map((f) => [f.path, f.content])) : newPolicyFile(p.name))
    setPolicy(p)
    setDraft(d)
    setActive((cur) => (cur in d ? cur : Object.keys(d).sort()[0] ?? ""))
    setProblems([])
  }, [])

  useEffect(() => {
    let cancelled = false
    fetchPolicy(client, name).then((r) => {
      if (cancelled) return
      if (r.ok) load(r.value)
      else setLoadError(r.error)
    })
    fetchStatus(client, name).then((r) => !cancelled && setStatus(r.ok ? r.value : null))
    return () => {
      cancelled = true
    }
  }, [name, load, reload])

  const changes = useMemo(() => (policy ? changedFiles(policy, draft) : {}), [policy, draft])
  const changeCount = Object.keys(changes).length
  const files = Object.keys(draft).sort()
  const fileProblems = (path: string) => problems.filter((p) => p.file === `${name}/${path}`)

  const run = async (what: Busy, fn: () => Promise<void>) => {
    setBusy(what)
    try {
      await fn()
    } finally {
      setBusy("")
    }
  }

  const format = () => run("format", async () => {
    if (!active.endsWith(".rego")) return
    const r = await formatFile(client, name, active, draft[active])
    if (!r.ok) return void toast.error(r.error)
    if (r.value.problems.length > 0) return setProblems(r.value.problems)
    setDraft((d) => ({ ...d, [active]: r.value.content ?? d[active] }))
    setProblems([])
  })

  const check = () => run("check", async () => {
    const r = await checkDraft(client, name, draft)
    if (!r.ok) return void toast.error(r.error)
    setProblems(r.value)
    setOutput(r.value.length === 0 ? "No problems found." : `${r.value.length} problem(s) found.`)
  })

  const evaluate = () => run("evaluate", async () => {
    const input = parseJSON(inputText, "INPUT")
    const data = parseJSON(dataText, "DATA")
    if (!input.ok) return void toast.error(input.error)
    if (!data.ok) return void toast.error(data.error)
    const r = await evaluateDraft(client, name, draft, query, input.value, data.value)
    if (!r.ok) return void toast.error(r.error)
    setProblems(r.value.problems ?? [])
    const values = (r.value.result ?? []).map((row) =>
      row.expressions.length === 1 && !row.bindings ? row.expressions[0].value : row)
    const shown = values.length === 0 ? "undefined" : JSON.stringify(values.length === 1 ? values[0] : values, null, 2)
    const ms = (r.value.durationNs / 1e6).toFixed(1)
    setOutput(`# ${r.value.query} (${ms} ms)\n${shown}${r.value.output ? `\n\n# print output\n${r.value.output}` : ""}`)
  })

  const test = () => run("test", async () => {
    const data = parseJSON(dataText, "DATA")
    if (!data.ok) return void toast.error(data.error)
    const r = await testDraft(client, name, draft, data.value)
    if (!r.ok) return void toast.error(r.error)
    setProblems(r.value.problems ?? [])
    const lines = r.value.results.map((t) =>
      `${t.pass ? "PASS" : t.skip ? "SKIP" : "FAIL"}  ${t.package}.${t.name}  (${t.file}:${t.row})${t.error && t.error !== "fail" ? `  ${t.error}` : ""}${t.output ? `\n${t.output}` : ""}`)
    setOutput(`${r.value.passed} passed, ${r.value.failed} failed\n\n${lines.join("\n") || "No tests found: name rules test_… in a _test.rego file."}`)
  })

  const publish = () => run("publish", async () => {
    if (!policy) return
    const r = await publishDraft(client, policy, draft, message)
    if (!r.ok) return void toast.error(r.error)
    setPublished(r.value)
    toast.success(`Opened pull request #${r.value.pullRequest.number}`)
  })

  // addFile adds a path PolicyAddFileDialog has validated.
  const addFile = (path: string) => {
    setDraft((d) => ({ ...d, [path]: path.endsWith(".rego") ? `package ${name.replace(/-/g, "_")}\n` : "{}\n" }))
    setActive(path)
  }

  // removeFile drops a file from the draft once the user confirmed; publishing deletes it.
  const removeFile = (path: string) => {
    setDraft((d) => {
      const next = { ...d }
      delete next[path]
      return next
    })
    if (active === path) setActive(files.find((f) => f !== path) ?? "")
    setFileToRemove(null)
  }

  if (loadError) {
    return <p className="container mx-auto px-6 py-10 text-sm text-destructive">{loadError} <Link className="underline" href="/policies">Back to policies</Link></p>
  }
  if (!policy) return <p className="container mx-auto px-6 py-10 text-sm text-muted-foreground">Loading…</p>

  const isNew = policy.files.length === 0

  return (
    <main className="bg-background">
      <div className="mx-auto px-4">
        <div className="flex flex-wrap items-center gap-2 border-b py-3">
          <Link href="/policies" className="text-muted-foreground hover:text-foreground" title="Back to policies">
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <h1 className="text-lg font-semibold tracking-tight">{name}</h1>
          <Badge variant="outline">{isNew ? "new" : policy.latestVersion ?? "unversioned"}</Badge>
          {status?.checked && (
            <Badge variant="outline" title="What OPA has loaded"
              className={status.loaded ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400" : "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400"}>
              {status.loaded ? `OPA: ${status.liveVersion === "head" ? "branch head" : status.liveVersion}` : "OPA: not loaded"}
            </Badge>
          )}
          <span className="font-mono text-xs text-muted-foreground" title={policy.commit}>{policy.ref}@{policy.commit.slice(0, 8)}</span>
          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            <Button variant="outline" size="sm" onClick={() => void format()} disabled={!!busy || !active.endsWith(".rego")}>
              <Wand2 className="mr-1 h-3.5 w-3.5" /> Format
            </Button>
            <Button variant="outline" size="sm" onClick={() => void check()} disabled={!!busy}>
              <CheckCircle2 className="mr-1 h-3.5 w-3.5" /> Check
            </Button>
            <Button variant="outline" size="sm" onClick={() => void evaluate()} disabled={!!busy}>
              <Play className="mr-1 h-3.5 w-3.5" /> Evaluate
            </Button>
            <Button variant="outline" size="sm" onClick={() => void test()} disabled={!!busy}>
              <TestTube2 className="mr-1 h-3.5 w-3.5" /> Test
            </Button>
            <Button size="sm" onClick={() => { setPublished(null); setPublishing(true) }} disabled={!!busy || changeCount === 0}
              title={changeCount === 0 ? "No changes to publish" : `${changeCount} changed file(s)`}>
              <Send className="mr-1 h-3.5 w-3.5" /> Publish{changeCount > 0 ? ` (${changeCount})` : ""}
            </Button>
          </div>
        </div>

        <Tabs value={tab} onValueChange={setTab} className="pt-2">
          <TabsList>
            <TabsTrigger value="editor">Editor</TabsTrigger>
            <TabsTrigger value="history" disabled={isNew}>Versions and pending changes</TabsTrigger>
          </TabsList>

          <TabsContent value="editor">
            <div className="grid gap-3 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
              <section className="flex min-h-[60vh] flex-col rounded-md border lg:h-[calc(100vh-10.5rem)]">
                <div className="flex flex-wrap items-center gap-1 border-b px-1 py-1" role="tablist" aria-label="Files">
                  {files.map((f) => (
                    <span key={f} className={`group flex items-center rounded px-2 py-1 font-mono text-xs ${f === active ? "bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-muted"}`}>
                      <button role="tab" aria-selected={f === active} onClick={() => setActive(f)}>
                        {f}{f in changes ? " •" : ""}{fileProblems(f).length > 0 ? ` (${fileProblems(f).length})` : ""}
                      </button>
                      <button className="ml-1 opacity-0 group-hover:opacity-100" onClick={() => setFileToRemove(f)} title={`Remove ${f}`} aria-label={`Remove ${f}`}>
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                  <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => setAddingFile(true)}>
                    <FilePlus className="mr-1 h-3 w-3" /> Add file
                  </Button>
                </div>
                {active ? (
                  <CodeEditor key={active} className="min-h-0 flex-1 overflow-auto" ariaLabel={`Edit ${active}`}
                    language={languageOf(active)} value={draft[active] ?? ""} problems={fileProblems(active)}
                    onChange={(v) => setDraft((d) => ({ ...d, [active]: v }))} />
                ) : (
                  <p className="p-4 text-sm text-muted-foreground">No files. Add one to start.</p>
                )}
              </section>

              <aside className="flex min-h-[60vh] flex-col gap-2 lg:h-[calc(100vh-10.5rem)]">
                <div className="rounded-md border">
                  <div className={panelTitle}>Query</div>
                  <Input className="rounded-none border-0 font-mono text-xs" aria-label="Query"
                    placeholder={`data.${(policy.packages[0] ?? name).replace(/-/g, "_")} (default: the policy's package)`}
                    value={query} onChange={(e) => setQuery(e.target.value)} />
                </div>
                <div className="flex min-h-0 flex-1 flex-col rounded-md border">
                  <div className={panelTitle}>Input</div>
                  <CodeEditor className="min-h-0 flex-1 overflow-auto" ariaLabel="Input" language="json" value={inputText} onChange={setInputText} />
                </div>
                <div className="flex min-h-0 flex-1 flex-col rounded-md border">
                  <div className={panelTitle}>Data <span className="font-normal normal-case">merged over the policy&apos;s data files</span></div>
                  <CodeEditor className="min-h-0 flex-1 overflow-auto" ariaLabel="Data" language="json" value={dataText} onChange={setDataText} />
                </div>
                <div className="flex min-h-0 flex-1 flex-col rounded-md border">
                  <div className={panelTitle}>Output {busy && <span className="font-normal normal-case">running {busy}…</span>}</div>
                  <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap p-2 font-mono text-xs" aria-label="Output">{output}</pre>
                </div>
                <div className="max-h-40 overflow-auto rounded-md border">
                  <div className={panelTitle}>Problems {problems.length > 0 && <span>({problems.length})</span>}</div>
                  {problems.length === 0 ? (
                    <p className="p-2 text-xs text-muted-foreground">No problems</p>
                  ) : (
                    <ul className="divide-y text-xs">
                      {problems.map((p, i) => {
                        const path = p.file?.startsWith(`${name}/`) ? p.file.slice(name.length + 1) : ""
                        return (
                          <li key={i}>
                            <button className="w-full px-2 py-1 text-left font-mono hover:bg-muted" onClick={() => path in draft && setActive(path)}>
                              <span className="text-destructive">{path || p.file || "query"}{p.row ? `:${p.row}:${p.col ?? 0}` : ""}</span> {p.message}
                            </button>
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </div>
              </aside>
            </div>
          </TabsContent>

          <TabsContent value="history">
            {!isNew && (
              <PolicyHistory name={name} onRestore={(files, version) => {
                load(policy, files)
                setTab("editor")
                toast.info(`Loaded ${version} into the editor. Publish to make it the next version.`)
              }} />
            )}
          </TabsContent>
        </Tabs>
      </div>

      <PolicyAddFileDialog open={addingFile} onOpenChange={setAddingFile} existing={files} onAdd={addFile} />
      <DeleteConfirmationDialog
        open={fileToRemove !== null}
        onOpenChange={(open) => !open && setFileToRemove(null)}
        onConfirm={() => fileToRemove && removeFile(fileToRemove)}
        title="Remove file"
        itemName={fileToRemove ?? ""}
        description={`Remove ${fileToRemove} from the draft? Publishing deletes it from the policy; until then, reloading the policy brings it back.`}
        irreversible={false}
      />

      <Dialog open={publishing} onOpenChange={(open) => !open && busy !== "publish" && setPublishing(false)}>
        <DialogContent className="max-w-lg" onClose={() => busy !== "publish" && setPublishing(false)}>
          <DialogHeader>
            <DialogTitle>Publish {name}</DialogTitle>
            <DialogDescription>
              Opens a pull request into the tracked branch. It goes live when an approver merges it, and is then tagged as the next version.
            </DialogDescription>
          </DialogHeader>
          {published ? (
            <div className="space-y-2 text-sm">
              <p>Pull request <a className="font-medium underline" href={published.pullRequest.url} target="_blank" rel="noreferrer">#{published.pullRequest.number}</a> is open on branch <span className="font-mono text-xs">{published.branch}</span>.</p>
              <DialogFooter>
                <Button onClick={() => { setPublishing(false); setMessage(""); setReload((n) => n + 1) }}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            <>
              <ul className="max-h-40 overflow-auto rounded-md bg-muted p-2 font-mono text-xs">
                {Object.entries(changes).map(([path, content]) => (
                  <li key={path}>{content === null ? "deleted" : path in Object.fromEntries(policy.files.map((f) => [f.path, 1])) ? "changed" : "added"}  {path}</li>
                ))}
              </ul>
              <Textarea aria-label="Commit message" rows={4} value={message} onChange={(e) => setMessage(e.target.value)}
                placeholder={"Summary of the change (the pull request's title)\n\nWhy it is needed."} />
              <DialogFooter>
                <Button variant="outline" onClick={() => setPublishing(false)} disabled={busy === "publish"}>Cancel</Button>
                <Button onClick={() => void publish()} disabled={busy === "publish" || !message.trim()}>
                  {busy === "publish" ? "Publishing…" : "Open pull request"}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </main>
  )
}
