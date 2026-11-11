// Settings for the platform resource pages (Runtimes, Models, Plugins,
// Secrets): how each kind is listed, summarized and created.

// AdminItem is a resource as the list endpoints return it.
export interface AdminItem {
  apiVersion?: string
  kind?: string
  metadata: { namespace?: string; name: string; tag?: string; [key: string]: unknown }
  spec?: Record<string, unknown>
  status?: Record<string, unknown>
}

export interface ResourceKind {
  kind: string
  plural: string
  title: string
  description: string
  // Tagged kinds keep versions; a delete names the tag.
  tagged: boolean
  // template is the YAML a new resource starts from.
  template: string
  summary: (item: AdminItem) => string
}

function str(v: unknown): string {
  return typeof v === "string" ? v : ""
}

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

export type ResourceKindName = "Runtime" | "Model" | "Plugin" | "Secret"

export const RESOURCE_KINDS: Record<ResourceKindName, ResourceKind> = {
  Runtime: {
    kind: "Runtime",
    plural: "runtimes",
    title: "Runtimes",
    description: "Where deployments run.",
    tagged: false,
    template: `apiVersion: ar.dev/v1alpha1
kind: Runtime
metadata:
  namespace: default
  name: my-runtime
spec:
  type: Kagent
  config:
    kagentUrl: http://kagent-controller.kagent.svc:8083
    namespace: kagent
`,
    summary: (item) => str(item.spec?.type) || "unknown type",
  },
  Model: {
    kind: "Model",
    plural: "models",
    title: "Models",
    description: "The models deployments use, with their provider and authentication.",
    tagged: true,
    template: `apiVersion: ar.dev/v1alpha1
kind: Model
metadata:
  namespace: default
  name: default
spec:
  title: My model
  provider: bedrock
  model: us.anthropic.claude-opus-4-8
  auth:
    strategy: runtime
`,
    summary: (item) => [str(item.spec?.provider), str(item.spec?.model)].filter(Boolean).join(" · ") || "no model",
  },
  Plugin: {
    kind: "Plugin",
    plural: "plugins",
    title: "Plugins",
    description: "Bundles of skills and commands, pinned to a source.",
    tagged: true,
    template: `apiVersion: ar.dev/v1alpha1
kind: Plugin
metadata:
  namespace: default
  name: my-plugin
spec:
  title: My plugin
  source:
    type: git
    git:
      repository:
        url: https://github.com/example/plugin
      reference: main
`,
    summary: (item) => {
      const source = obj(item.spec?.source)
      const repo = str(obj(obj(source.git).repository).url)
      return [str(source.type), repo].filter(Boolean).join(" · ") || "no source"
    },
  },
  Secret: {
    kind: "Secret",
    plural: "secrets",
    title: "Secrets",
    description: "Credentials referenced by runtimes and models. Values are write-only and never shown.",
    tagged: false,
    template: `apiVersion: ar.dev/v1alpha1
kind: Secret
metadata:
  namespace: default
  name: my-secret
spec:
  stringData:
    api-key: replace-me
`,
    summary: (item) => {
      const keys = item.status?.dataKeys
      return Array.isArray(keys) && keys.length > 0 ? `keys: ${keys.join(", ")}` : "no keys"
    },
  },
}

// deleteDocument is the /v0/apply document that deletes item. It is JSON,
// which the YAML endpoint accepts, so names are always quoted safely.
export function deleteDocument(kind: ResourceKind, item: AdminItem): string {
  const metadata: Record<string, string> = { namespace: item.metadata.namespace || "default", name: item.metadata.name }
  if (kind.tagged && item.metadata.tag) metadata.tag = item.metadata.tag
  return JSON.stringify({ apiVersion: "ar.dev/v1alpha1", kind: kind.kind, metadata })
}

export interface ApplyResult {
  kind?: string
  name: string
  status: string
  error?: string
}

// failedResults returns the documents /v0/apply could not apply or delete;
// the endpoint answers 200 and reports failures per document.
export function failedResults(results: ApplyResult[] | undefined): ApplyResult[] {
  return (results ?? []).filter((r) => r.status === "failed")
}
