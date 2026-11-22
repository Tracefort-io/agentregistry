import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi, beforeEach } from "vitest"

const applyBatch = vi.fn()
vi.mock("@/lib/admin-api", () => ({
  applyBatch: (...a: unknown[]) => applyBatch(...a),
}))

const toast = vi.hoisted(() => ({ success: vi.fn(), info: vi.fn(), error: vi.fn() }))
vi.mock("sonner", () => ({ toast }))

import { YamlApplyPanel } from "@/components/yaml-apply-panel"

const template = "apiVersion: ar.dev/v1alpha1\nkind: MCPServer\nmetadata:\n  name: x\n"

function renderPanel() {
  const onApplied = vi.fn()
  const onCancel = vi.fn()
  render(<YamlApplyPanel kind="MCPServer" initialYaml={template} onApplied={onApplied} onCancel={onCancel} />)
  return { onApplied, onCancel }
}

describe("YamlApplyPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("sends the edited YAML to /v0/apply and reports what was applied", async () => {
    applyBatch.mockResolvedValue({ data: { results: [{ kind: "MCPServer", name: "x", status: "created" }] }, response: { ok: true, status: 200 } })
    const { onApplied } = renderPanel()
    const editor = screen.getByRole("textbox", { name: "MCPServer YAML" })
    expect(editor).toHaveValue(template)
    await userEvent.type(editor, "  tag: v2\n")
    await userEvent.click(screen.getByRole("button", { name: "Apply" }))

    const body = applyBatch.mock.calls[0][0].body as Blob
    expect(body.type).toBe("application/yaml")
    expect(await body.text()).toBe(template + "  tag: v2\n")
    expect(toast.success).toHaveBeenCalledWith("Applied MCPServer x: created")
    expect(onApplied).toHaveBeenCalled()
  })

  it("says a held change needs approval instead of reporting it applied", async () => {
    applyBatch.mockResolvedValue({
      data: { results: [{ kind: "MCPServer", name: "x", status: "pending-approval", approvalRequest: "arq_1" }] },
      response: { ok: true, status: 200 },
    })
    const { onApplied } = renderPanel()
    await userEvent.click(screen.getByRole("button", { name: "Apply" }))

    expect(toast.info).toHaveBeenCalledWith(expect.stringContaining("MCPServer x needs approval"))
    expect(toast.success).not.toHaveBeenCalled()
    expect(onApplied).toHaveBeenCalled()
  })

  it.each([
    ["a failed document", { data: { results: [{ kind: "MCPServer", name: "x", status: "failed", error: "default/x@1.0.0 was deleted" }] }, response: { ok: true, status: 200 } }, "MCPServer x: default/x@1.0.0 was deleted"],
    ["an HTTP error", { data: undefined, response: { ok: false, status: 401 } }, "MCPServer MCPServer: HTTP 401"],
  ])("lists %s and stays open", async (_, reply, message) => {
    applyBatch.mockResolvedValue(reply)
    const { onApplied } = renderPanel()
    await userEvent.click(screen.getByRole("button", { name: "Apply" }))

    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(onApplied).not.toHaveBeenCalled()
    expect(toast.success).not.toHaveBeenCalled()
  })

  it("does not apply empty YAML", async () => {
    renderPanel()
    await userEvent.clear(screen.getByRole("textbox", { name: "MCPServer YAML" }))
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled()
  })
})
