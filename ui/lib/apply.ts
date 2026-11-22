import { toast } from "sonner"
import { applyBatch } from "@/lib/admin-api"
import { ApplyResult, failedResults, pendingResults, yamlBody } from "@/lib/resource-kinds"

// ApplyOutcome sorts what POST /v0/apply did with a set of documents. The
// endpoint answers 200 and reports each document; httpError is set when the
// request itself failed.
export interface ApplyOutcome {
  httpError?: string
  failed: ApplyResult[]
  pending: ApplyResult[]
  applied: ApplyResult[]
}

// applyDocuments sends YAML in the arctl apply format (several documents may
// be separated by ---) to /v0/apply, which holds a change that needs
// approval.
export async function applyDocuments(yaml: string): Promise<ApplyOutcome> {
  const { data, response } = await applyBatch({ body: yamlBody(yaml) })
  if (!response?.ok) {
    return { httpError: `HTTP ${response?.status ?? "error"}`, failed: [], pending: [], applied: [] }
  }
  const results = (data?.results ?? []) as ApplyResult[]
  const pending = pendingResults(results)
  const failed = failedResults(results)
  return {
    failed,
    pending,
    applied: results.filter((r) => !failed.includes(r) && !pending.includes(r)),
  }
}

// reportApplied tells the user what a successful apply did: which documents
// wait for approval and which were applied. kind names documents whose
// result carries none.
export function reportApplied(outcome: ApplyOutcome, kind: string) {
  if (outcome.pending.length > 0) {
    toast.info(`${outcome.pending.map((r) => `${r.kind ?? kind} ${r.name}`).join(", ")} needs approval. It will be applied once approved; follow it under Approvals.`)
  }
  if (outcome.applied.length > 0) {
    toast.success(`Applied ${outcome.applied.map((r) => `${r.kind ?? kind} ${r.name}: ${r.status}`).join(", ")}`)
  }
}
