import { Suspense } from "react"
import { PolicyEditorPage } from "@/components/policy-editor"

// The policy is chosen by ?policy=, read on the client: the UI is a static export.
export default function PolicyEditPage() {
  return (
    <Suspense fallback={<p className="container mx-auto px-6 py-10 text-sm text-muted-foreground">Loading…</p>}>
      <PolicyEditorPage />
    </Suspense>
  )
}
