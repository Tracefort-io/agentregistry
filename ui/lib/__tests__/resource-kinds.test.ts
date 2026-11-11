import { describe, it, expect } from "vitest"
import { deleteDocument, failedResults, RESOURCE_KINDS } from "../resource-kinds"

describe("summaries", () => {
  it.each([
    ["Runtime", { metadata: { name: "k8s" }, spec: { type: "Kubernetes" } }, "Kubernetes"],
    ["Runtime", { metadata: { name: "x" } }, "unknown type"],
    ["Model", { metadata: { name: "default" }, spec: { provider: "bedrock", model: "us.anthropic.claude" } }, "bedrock · us.anthropic.claude"],
    ["Plugin", { metadata: { name: "p" }, spec: { source: { type: "git", git: { repository: { url: "https://g/r" } } } } }, "git · https://g/r"],
    ["Plugin", { metadata: { name: "p" }, spec: {} }, "no source"],
    ["Secret", { metadata: { name: "s" }, status: { dataKeys: ["api-key", "token"] } }, "keys: api-key, token"],
    ["Secret", { metadata: { name: "s" } }, "no keys"],
  ] as const)("%s %j -> %s", (kind, item, want) => {
    expect(RESOURCE_KINDS[kind].summary(item)).toBe(want)
  })

  it("never shows secret values", () => {
    const summary = RESOURCE_KINDS.Secret.summary({
      metadata: { name: "s" },
      spec: { stringData: { "api-key": "do-not-show" } },
      status: { dataKeys: ["api-key"] },
    })
    expect(summary).not.toContain("do-not-show")
  })
})

describe("deleteDocument", () => {
  it("names the tag of a tagged kind", () => {
    const doc = JSON.parse(deleteDocument(RESOURCE_KINDS.Model, { metadata: { namespace: "team", name: "gpt", tag: "v2" } }))
    expect(doc).toEqual({ apiVersion: "ar.dev/v1alpha1", kind: "Model", metadata: { namespace: "team", name: "gpt", tag: "v2" } })
  })

  it("omits the tag of a mutable kind and defaults the namespace", () => {
    const doc = JSON.parse(deleteDocument(RESOURCE_KINDS.Runtime, { metadata: { name: "k8s", tag: "ignored" } }))
    expect(doc.metadata).toEqual({ namespace: "default", name: "k8s" })
  })

  it("keeps hostile names inside a JSON string", () => {
    const name = 'x"\nkind: Secret\nmetadata: {name: other}'
    const doc = JSON.parse(deleteDocument(RESOURCE_KINDS.Runtime, { metadata: { name } }))
    expect(doc.kind).toBe("Runtime")
    expect(doc.metadata.name).toBe(name)
  })
})

describe("failedResults", () => {
  it("returns only failures", () => {
    expect(failedResults([
      { name: "a", status: "created" },
      { name: "b", status: "failed", error: "forbidden: not permitted" },
      { name: "c", status: "deleted" },
    ])).toEqual([{ name: "b", status: "failed", error: "forbidden: not permitted" }])
    expect(failedResults(undefined)).toEqual([])
  })
})
