import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi, beforeEach } from "vitest"

const plugin = { apiVersion: "ar.dev/v1alpha1", kind: "Plugin", metadata: { namespace: "default", name: "audit-hook" }, spec: {} }

const get = vi.fn()
const deleteBatch = vi.fn()
vi.mock("@/lib/admin-api", () => ({
  client: { get: (...a: unknown[]) => get(...a) },
  applyBatch: vi.fn(),
  deleteBatch: (...a: unknown[]) => deleteBatch(...a),
}))

// A writer: Plugin changes need an approval.
let allowed = false
let requestable = true
vi.mock("@/lib/permissions", () => ({
  useCan: () => () => allowed,
  useCanRequest: () => () => requestable,
}))

const toast = vi.hoisted(() => ({ success: vi.fn(), info: vi.fn(), error: vi.fn() }))
vi.mock("sonner", () => ({ toast }))

import { ResourceAdmin } from "@/components/resource-admin"

async function deleteThePlugin() {
  await userEvent.click(await screen.findByRole("button", { name: "Delete" }))
  const dialog = await screen.findByRole("dialog", { name: "Delete Plugin" })
  await userEvent.click(within(dialog).getByRole("button", { name: "Remove" }))
}

describe("ResourceAdmin with changes that need approval", () => {
  beforeEach(() => {
    allowed = false
    requestable = true
    get.mockResolvedValue({ data: { items: [plugin] }, response: { ok: true, status: 200 } })
    deleteBatch.mockReset()
    vi.clearAllMocks()
  })

  it("offers adding and deleting to a user who may ask for them", async () => {
    render(<ResourceAdmin kindName="Plugin" />)
    expect(await screen.findByRole("button", { name: "Delete" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument()
  })

  it("offers neither when the user may not even ask", async () => {
    requestable = false
    render(<ResourceAdmin kindName="Plugin" />)
    expect(await screen.findByText("audit-hook")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull()
    expect(screen.queryByRole("button", { name: "Add" })).toBeNull()
  })

  it("says a held delete needs approval instead of reporting it deleted", async () => {
    deleteBatch.mockResolvedValue({
      data: { results: [{ kind: "Plugin", name: "audit-hook", status: "pending-approval", approvalRequest: "arq_1" }] },
      response: { ok: true, status: 200 },
    })
    render(<ResourceAdmin kindName="Plugin" />)

    await deleteThePlugin()

    await waitFor(() => expect(toast.info).toHaveBeenCalledWith(expect.stringContaining("needs approval")))
    expect(toast.success).not.toHaveBeenCalled()
  })

  it("reports a delete that was applied", async () => {
    allowed = true
    deleteBatch.mockResolvedValue({
      data: { results: [{ kind: "Plugin", name: "audit-hook", status: "deleted" }] },
      response: { ok: true, status: 200 },
    })
    render(<ResourceAdmin kindName="Plugin" />)

    await deleteThePlugin()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith("Deleted default/audit-hook"))
    expect(toast.info).not.toHaveBeenCalled()
  })
})
