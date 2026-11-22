import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi, beforeEach } from "vitest"

const createServerV0 = vi.fn()
const applyBatch = vi.fn()
vi.mock("@/lib/admin-api", () => ({
  createServerV0: (...a: unknown[]) => createServerV0(...a),
  applyBatch: (...a: unknown[]) => applyBatch(...a),
  PendingApprovalError: class extends Error {},
}))

const toast = vi.hoisted(() => ({ success: vi.fn(), info: vi.fn(), error: vi.fn() }))
vi.mock("sonner", () => ({ toast }))

import { AddServerDialog } from "@/components/add-server-dialog"

function renderDialog() {
  const onServerAdded = vi.fn()
  const onOpenChange = vi.fn()
  render(<AddServerDialog open onOpenChange={onOpenChange} onServerAdded={onServerAdded} />)
  return { onServerAdded, onOpenChange }
}

// fillHTTPServer fills the form for an OCI server with http transport.
async function fillHTTPServer(path: string) {
  await userEvent.type(screen.getByLabelText("Server Name *"), "weather")
  await userEvent.clear(screen.getByLabelText("Tag *"))
  await userEvent.type(screen.getByLabelText("Tag *"), "1.0.0")
  await userEvent.type(screen.getByLabelText("Description *"), "Weather tools")
  await userEvent.click(screen.getByRole("button", { name: "Add Package" }))
  await userEvent.selectOptions(screen.getByRole("combobox"), "oci")
  await userEvent.type(screen.getByPlaceholderText("Package identifier"), "registry.example.com/weather:1.0.0")
  await userEvent.type(screen.getByLabelText("Upstream catalogue name (mcpName) *"), "io.example/weather")
  await userEvent.click(screen.getByRole("radio", { name: "http" }))
  await userEvent.clear(screen.getByLabelText("Port *:"))
  await userEvent.type(screen.getByLabelText("Port *:"), "8765")
  if (path) await userEvent.type(screen.getByLabelText("Path:"), path)
}

describe("AddServerDialog form", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    createServerV0.mockResolvedValue({ data: { server: { name: "weather" } } })
  })

  it.each([
    ["with a path", "/mcp", { type: "http", port: 8765, path: "/mcp" }],
    ["without one", "", { type: "http", port: 8765 }],
  ])("sends the http transport %s", async (_, path, transport) => {
    const { onServerAdded } = renderDialog()
    await fillHTTPServer(path)
    await userEvent.click(screen.getByRole("button", { name: "Create Server" }))

    const body = createServerV0.mock.calls[0][0].body
    expect(body.source.package.transport).toEqual(transport)
    expect(body.source.package.origin).toEqual({ type: "oci", identifier: "registry.example.com/weather:1.0.0", oci: { serverName: "io.example/weather" } })
    expect(onServerAdded).toHaveBeenCalled()
  })

  it("refuses a path that does not start with /", async () => {
    renderDialog()
    await fillHTTPServer("mcp")
    await userEvent.click(screen.getByRole("button", { name: "Create Server" }))

    expect(toast.error).toHaveBeenCalledWith("http transport path must start with /, for example /mcp")
    expect(createServerV0).not.toHaveBeenCalled()
  })
})

describe("AddServerDialog YAML", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("starts from a whole MCPServer document and applies it", async () => {
    applyBatch.mockResolvedValue({ data: { results: [{ kind: "MCPServer", name: "my-server", status: "pending-approval" }] }, response: { ok: true, status: 200 } })
    const { onServerAdded, onOpenChange } = renderDialog()
    await userEvent.click(screen.getByRole("button", { name: "YAML" }))

    const editor = screen.getByRole("textbox", { name: "MCPServer YAML" }) as HTMLTextAreaElement
    expect(editor.value).toContain("kind: MCPServer")
    expect(editor.value).toContain("path: /mcp")
    await userEvent.click(screen.getByRole("button", { name: "Apply" }))

    const body = applyBatch.mock.calls[0][0].body as Blob
    expect(await body.text()).toBe(editor.value)
    expect(toast.info).toHaveBeenCalledWith(expect.stringContaining("needs approval"))
    expect(onOpenChange).toHaveBeenCalledWith(false)
    expect(onServerAdded).toHaveBeenCalled()
  })
})
