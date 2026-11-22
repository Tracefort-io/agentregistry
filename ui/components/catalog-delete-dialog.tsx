"use client"

import { useState } from "react"
import { toast } from "sonner"
import { deleteBatch } from "@/lib/admin-api"
import { ApplyResult, deleteAllTagsDocument, failedResults, pendingResults, yamlBody } from "@/lib/resource-kinds"
import { DeleteConfirmationDialog } from "@/components/delete-confirmation-dialog"

// CatalogDeleteTarget is a catalog entry to delete: every live tag of one
// name of a tagged kind (MCPServer, Skill, Agent).
export interface CatalogDeleteTarget {
  kind: string
  label: string
  namespace?: string
  name: string
  tags: string[]
}

// CatalogDeleteDialog confirms and deletes a catalog entry through
// /v0/apply, which holds the delete when it needs approval. The registry
// keeps the deleted versions, marked deleted, and their tags can't be
// applied again.
export function CatalogDeleteDialog({ target, onClose, onDeleted }: {
  target: CatalogDeleteTarget | null
  onClose: () => void
  onDeleted: () => void
}) {
  const [deleting, setDeleting] = useState(false)
  const ref = target ? `${target.namespace || "default"}/${target.name}` : ""

  async function confirm() {
    if (!target) return
    setDeleting(true)
    const { data, response } = await deleteBatch({ body: yamlBody(deleteAllTagsDocument(target.kind, target.namespace, target.name)) })
    setDeleting(false)
    const results = data?.results as ApplyResult[] | undefined
    const failed = failedResults(results)
    if (!response?.ok || failed.length > 0) {
      toast.error(failed[0]?.error || `Could not delete ${ref} (HTTP ${response?.status ?? "error"}).`)
      return
    }
    if (pendingResults(results).length > 0) {
      toast.info(`Deleting ${ref} needs approval. It will be deleted once approved; follow it under Approvals.`)
    } else {
      toast.success(`Deleted ${ref}`)
    }
    onClose()
    onDeleted()
  }

  const tags = target?.tags.length ? ` and its tag${target.tags.length > 1 ? "s" : ""} ${target.tags.join(", ")}` : ""
  return (
    <DeleteConfirmationDialog
      open={target !== null}
      onOpenChange={(open) => !open && !deleting && onClose()}
      onConfirm={() => void confirm()}
      title={target ? `Delete ${target.label}` : ""}
      itemName={ref}
      description={`Delete ${ref}${tags}? The registry keeps deleted versions in its history but no longer serves them, and their tags can't be applied again.`}
      isDeleting={deleting}
    />
  )
}
