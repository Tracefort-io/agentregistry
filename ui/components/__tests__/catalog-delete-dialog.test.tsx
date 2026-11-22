import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi, beforeEach } from "vitest"

const deleteBatch = vi.fn()
vi.mock("@/lib/admin-api", () => ({
  deleteBatch: (...a: unknown[]) => deleteBatch(...a),
}))

const toast = vi.hoisted(() => ({ success: vi.fn(), info: vi.fn(), error: vi.fn() }))
vi.mock("sonner", () => ({ toast }))

import { CatalogDeleteDialog, type CatalogDeleteTarget } from "@/components/catalog-delete-dialog"

const target: CatalogDeleteTarget = { kind: "MCPServer", label: "MCP server", namespace: "default", name: "weather", tags: ["1.0.0", "0.9.0"] }

function renderDialog() {
  const onClose = vi.fn()
  const onDeleted = vi.fn()
  render(<CatalogDeleteDialog target={target} onClose={onClose} onDeleted={onDeleted} />)
  return { onClose, onDeleted }
}

async function confirm() {
  const dialog = await screen.findByRole("dialog", { name: "Delete MCP server" })
  await userEvent.click(within(dialog).getByRole("button", { name: "Remove" }))
}

describe("CatalogDeleteDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("names the entry and its tags, and says deleted versions are kept", async () => {
    renderDialog()
    const dialog = await screen.findByRole("dialog", { name: "Delete MCP server" })
    expect(within(dialog).getByText(/default\/weather and its tags 1\.0\.0, 0\.9\.0/)).toBeInTheDocument()
    expect(within(dialog).getByText(/keeps deleted versions in its history/)).toBeInTheDocument()
  })

  it("deletes every tag through /v0/apply with one document that names no tag", async () => {
    deleteBatch.mockResolvedValue({ data: { results: [{ name: "weather", status: "deleted" }] }, response: { ok: true, status: 200 } })
    const { onClose, onDeleted } = renderDialog()
    await confirm()

    const body = deleteBatch.mock.calls[0][0].body as Blob
    expect(body.type).toBe("application/yaml")
    expect(JSON.parse(await body.text())).toEqual({ apiVersion: "ar.dev/v1alpha1", kind: "MCPServer", metadata: { namespace: "default", name: "weather" } })
    expect(toast.success).toHaveBeenCalledWith("Deleted default/weather")
    expect(onClose).toHaveBeenCalled()
    expect(onDeleted).toHaveBeenCalled()
  })

  it("says a held delete needs approval instead of reporting it deleted", async () => {
    deleteBatch.mockResolvedValue({
      data: { results: [{ kind: "MCPServer", name: "weather", status: "pending-approval", approvalRequest: "arq_1" }] },
      response: { ok: true, status: 200 },
    })
    const { onDeleted } = renderDialog()
    await confirm()

    expect(toast.info).toHaveBeenCalledWith(expect.stringContaining("needs approval"))
    expect(toast.success).not.toHaveBeenCalled()
    expect(onDeleted).toHaveBeenCalled()
  })

  it.each([
    ["a failed document", { data: { results: [{ name: "weather", status: "failed", error: "forbidden: no" }] }, response: { ok: true, status: 200 } }, "forbidden: no"],
    ["an HTTP error", { data: undefined, response: { ok: false, status: 503 } }, "Could not delete default/weather (HTTP 503)."],
  ])("reports %s and keeps the dialog open", async (_, reply, message) => {
    deleteBatch.mockResolvedValue(reply)
    const { onClose, onDeleted } = renderDialog()
    await confirm()

    expect(toast.error).toHaveBeenCalledWith(message)
    expect(onClose).not.toHaveBeenCalled()
    expect(onDeleted).not.toHaveBeenCalled()
  })
})
