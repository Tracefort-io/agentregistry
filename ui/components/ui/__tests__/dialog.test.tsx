import { useState } from "react"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi } from "vitest"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../dialog"

// Harness opens the dialog from a trigger button, as the app does.
function Harness({ onClose, onOpenChange }: { onClose?: () => void; onOpenChange?: (open: boolean) => void }) {
  const [open, setOpen] = useState(false)
  const change = (next: boolean) => {
    onOpenChange?.(next)
    setOpen(next)
  }
  return (
    <>
      <button onClick={() => setOpen(true)}>Open settings</button>
      <Dialog open={open} onOpenChange={change}>
        <DialogContent onClose={onClose ?? (() => setOpen(false))}>
          <DialogHeader>
            <DialogTitle>Settings</DialogTitle>
            <DialogDescription>Change how the registry behaves.</DialogDescription>
          </DialogHeader>
          <input aria-label="Name" />
          <DialogFooter>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button>Save</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

describe("Dialog accessibility", () => {
  it("is a dialog named by its title and described by its description", async () => {
    render(<Harness />)
    await userEvent.click(screen.getByRole("button", { name: "Open settings" }))
    const dialog = screen.getByRole("dialog", { name: "Settings" })
    expect(dialog).toHaveAccessibleDescription("Change how the registry behaves.")
  })

  it("moves focus into the dialog and keeps it there", async () => {
    render(<Harness />)
    await userEvent.click(screen.getByRole("button", { name: "Open settings" }))
    const dialog = screen.getByRole("dialog", { name: "Settings" })
    expect(dialog).toContainElement(document.activeElement as HTMLElement)
    for (let i = 0; i < 6; i++) {
      await userEvent.tab()
      expect(dialog).toContainElement(document.activeElement as HTMLElement)
    }
  })

  it("closes on Escape and returns focus to the trigger", async () => {
    const onOpenChange = vi.fn()
    render(<Harness onOpenChange={onOpenChange} />)
    const trigger = screen.getByRole("button", { name: "Open settings" })
    await userEvent.click(trigger)
    await userEvent.keyboard("{Escape}")
    expect(onOpenChange).toHaveBeenCalledWith(false)
    expect(screen.queryByRole("dialog")).toBeNull()
    // Radix moves focus back once the dialog has unmounted.
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  it("has a labelled close button that calls the caller's onClose", async () => {
    const onClose = vi.fn()
    render(<Harness onClose={onClose} />)
    await userEvent.click(screen.getByRole("button", { name: "Open settings" }))
    await userEvent.click(screen.getByRole("button", { name: "Close" }))
    expect(onClose).toHaveBeenCalled()
  })
})
