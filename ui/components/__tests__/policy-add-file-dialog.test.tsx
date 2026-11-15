import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, it, expect, vi } from "vitest"
import { PolicyAddFileDialog, pathError } from "../policy-add-file-dialog"

describe("pathError", () => {
  it.each([
    ["", ""],
    ["lib/helpers.rego", ""],
    ["roles/data.json", ""],
    ["run.sh", "Use a .rego file or data.json"],
    ["../escape.rego", "Use a .rego file or data.json"],
    ["data.yaml", "Use a .rego file or data.json"],
    ["registry.rego", "already exists"],
  ])("%s", (path, want) => {
    const got = pathError(path, ["registry.rego"])
    if (want) expect(got).toContain(want)
    else expect(got).toBe("")
  })
})

describe("PolicyAddFileDialog", () => {
  it("adds a valid path", async () => {
    const onAdd = vi.fn()
    const onOpenChange = vi.fn()
    render(<PolicyAddFileDialog open onOpenChange={onOpenChange} existing={["registry.rego"]} onAdd={onAdd} />)
    await userEvent.type(screen.getByRole("textbox", { name: "File path" }), "lib/helpers.rego")
    await userEvent.click(screen.getByRole("button", { name: "Add file" }))
    expect(onAdd).toHaveBeenCalledWith("lib/helpers.rego")
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it("explains an invalid path and won't add it", async () => {
    const onAdd = vi.fn()
    render(<PolicyAddFileDialog open onOpenChange={vi.fn()} existing={["registry.rego"]} onAdd={onAdd} />)
    await userEvent.type(screen.getByRole("textbox", { name: "File path" }), "registry.rego")
    expect(screen.getByRole("alert")).toHaveTextContent("That file already exists.")
    expect(screen.getByRole("button", { name: "Add file" })).toBeDisabled()
    await userEvent.type(screen.getByRole("textbox", { name: "File path" }), "{Enter}")
    expect(onAdd).not.toHaveBeenCalled()
  })
})
