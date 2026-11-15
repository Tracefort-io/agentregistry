import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi, beforeEach } from "vitest"
import type { FlatDeployment } from "@/lib/deployment-flat"

const deployment: FlatDeployment = {
  id: "default/bot", namespace: "default", name: "bot", tag: "latest", serverName: "bot",
  resourceType: "agent", runtimeId: "local", origin: "managed", status: "deployed",
  raw: {} as FlatDeployment["raw"],
}

const listDeployments = vi.fn()
const deleteDeployment = vi.fn()
vi.mock("@/lib/admin-api", () => ({
  listDeployments: (...a: unknown[]) => listDeployments(...a),
  deleteDeployment: (...a: unknown[]) => deleteDeployment(...a),
}))
vi.mock("@/lib/deployment-flat", () => ({ toFlatDeployment: (d: FlatDeployment) => d }))
vi.mock("@/lib/permissions", () => ({ useCan: () => () => true }))

import DeployedPage from "@/app/deployed/page"

// openAndConfirmRemoval clicks the row's Remove, then the dialog's.
async function openAndConfirmRemoval() {
  await userEvent.click(await screen.findByRole("button", { name: "Remove" }))
  const dialog = await screen.findByRole("dialog", { name: "Remove Deployment" })
  await userEvent.click(within(dialog).getByRole("button", { name: "Remove" }))
}

describe("DeployedPage removal", () => {
  beforeEach(() => {
    listDeployments.mockResolvedValue({ data: { items: [deployment] } })
    deleteDeployment.mockReset()
  })

  it("shows a failed removal in the dialog, without a browser alert", async () => {
    // happy-dom has no alert; stub it so a call would be caught.
    const alert = vi.fn()
    vi.stubGlobal("alert", alert)
    deleteDeployment.mockRejectedValue(new Error("runtime unreachable"))
    render(<DeployedPage />)

    await openAndConfirmRemoval()

    const dialog = screen.getByRole("dialog", { name: "Remove Deployment" })
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Could not remove the deployment: runtime unreachable")
    expect(alert).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })

  it("closes the dialog when the removal succeeds", async () => {
    deleteDeployment.mockResolvedValue({})
    render(<DeployedPage />)

    await openAndConfirmRemoval()

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(deleteDeployment).toHaveBeenCalledWith(expect.objectContaining({ path: { name: "bot" } }))
  })
})

