import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi } from "vitest"
import { DeleteConfirmationDialog } from "../delete-confirmation-dialog"

describe("DeleteConfirmationDialog", () => {
  it("warns that a removal is final by default", () => {
    render(<DeleteConfirmationDialog open onOpenChange={vi.fn()} onConfirm={vi.fn()} title="Remove agent" itemName="bot" />)
    expect(screen.getByText("This action cannot be undone.")).toBeInTheDocument()
  })

  it("leaves the warning out for a removal that can be taken back", async () => {
    const onConfirm = vi.fn()
    render(
      <DeleteConfirmationDialog open onOpenChange={vi.fn()} onConfirm={onConfirm} title="Remove file"
        itemName="e2e_demo.rego" description="Remove e2e_demo.rego from the draft?" irreversible={false} />,
    )
    expect(screen.queryByText("This action cannot be undone.")).toBeNull()
    expect(screen.getByText("Remove e2e_demo.rego from the draft?")).toBeInTheDocument()
    await userEvent.click(screen.getByRole("button", { name: "Remove" }))
    expect(onConfirm).toHaveBeenCalled()
  })
})
