"use client"

import { useState } from "react"
import { applyDocuments, reportApplied } from "@/lib/apply"
import { ApplyResult } from "@/lib/resource-kinds"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"

// YamlApplyPanel edits YAML in the arctl apply format and applies it
// through /v0/apply. Failed documents are listed and keep the panel open;
// otherwise it reports what was applied or held for approval and calls
// onApplied. kind names documents whose result carries no kind.
export function YamlApplyPanel({ kind, initialYaml, onCancel, onApplied, onBusyChange }: {
  kind: string
  initialYaml: string
  onCancel: () => void
  onApplied: () => void
  onBusyChange?: (busy: boolean) => void
}) {
  const [yaml, setYaml] = useState(initialYaml)
  const [applying, setApplying] = useState(false)
  const [errors, setErrors] = useState<ApplyResult[]>([])

  async function apply() {
    setApplying(true)
    onBusyChange?.(true)
    setErrors([])
    const outcome = await applyDocuments(yaml)
    setApplying(false)
    onBusyChange?.(false)
    if (outcome.httpError) {
      setErrors([{ name: kind, status: "failed", error: outcome.httpError }])
      return
    }
    if (outcome.failed.length > 0) {
      setErrors(outcome.failed)
      return
    }
    reportApplied(outcome, kind)
    setYaml(initialYaml)
    onApplied()
  }

  return (
    <div className="space-y-4">
      <Textarea
        value={yaml}
        onChange={(e) => setYaml(e.target.value)}
        className="min-h-[300px] font-mono text-xs"
        spellCheck={false}
        aria-label={`${kind} YAML`}
        disabled={applying}
      />
      {errors.length > 0 && (
        <ul className="space-y-1 text-sm text-destructive">
          {errors.map((r, i) => (
            <li key={i}>{`${r.kind ?? kind} ${r.name}: ${r.error ?? r.status}`}</li>
          ))}
        </ul>
      )}
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel} disabled={applying}>
          Cancel
        </Button>
        <Button onClick={() => void apply()} disabled={applying || !yaml.trim()}>
          {applying ? "Applying…" : "Apply"}
        </Button>
      </div>
    </div>
  )
}
