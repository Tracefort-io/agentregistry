"use client"

import { useState } from "react"
import { isPolicyFile } from "@/lib/policies"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"

interface PolicyAddFileDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  // existing are the draft's paths; a path can't be added twice.
  existing: string[]
  onAdd: (path: string) => void
}

// pathError explains why a path can't be added, or is "" when it can.
export function pathError(path: string, existing: string[]): string {
  if (!path) return ""
  if (!isPolicyFile(path)) return "Use a .rego file or data.json, at a relative path inside the policy."
  if (existing.includes(path)) return "That file already exists."
  return ""
}

// PolicyAddFileDialog asks for the path of a new file in the policy draft.
export function PolicyAddFileDialog({ open, onOpenChange, existing, onAdd }: PolicyAddFileDialogProps) {
  const [path, setPath] = useState("")
  const error = pathError(path, existing)

  const close = (next: boolean) => {
    if (!next) setPath("")
    onOpenChange(next)
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!path || error) return
    onAdd(path)
    close(false)
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-w-md" onClose={() => close(false)}>
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>Add a file</DialogTitle>
            <DialogDescription>
              A .rego file or data.json, at a path inside the policy, for example lib/helpers.rego or roles/data.json.
            </DialogDescription>
          </DialogHeader>
          <Input
            aria-label="File path"
            aria-invalid={!!error}
            placeholder="lib/helpers.rego"
            value={path}
            onChange={(e) => setPath(e.target.value.trim())}
            autoFocus
          />
          {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => close(false)}>Cancel</Button>
            <Button type="submit" disabled={!path || !!error}>Add file</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
