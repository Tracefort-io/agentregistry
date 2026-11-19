import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, it, expect, vi } from "vitest"
import type { ApprovalRequest, ApprovalReview } from "@/lib/approvals"
import { Approvals } from "../approvals"

const held: ApprovalRequest = {
  id: "arq_1", status: "pending", verb: "apply", kind: "Prompt", namespace: "default",
  name: "a-prompt-with-a-rather-long-name-that-used-to-be-cut-off", requesterSubject: "carol-sub",
  requesterUsername: "carol", createdAt: "2026-11-12T09:00:00Z", updatedAt: "2026-11-12T09:00:00Z",
}
const withdrawn: ApprovalRequest = { ...held, id: "arq_0", status: "cancelled", detail: "cancelled by carol" }

const api = vi.hoisted(() => ({
  mine: [] as ApprovalRequest[],
  reviews: [] as ApprovalReview[],
  cancelRequest: vi.fn(async () => ""),
}))

vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { profile: { sub: "carol-sub" } } }) }))
vi.mock("@/lib/admin-api", () => ({ client: {} }))
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock("@/lib/approvals", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/approvals")>()),
  fetchMyRequests: async () => ({ items: api.mine, error: "" }),
  fetchReviews: async () => ({ items: api.reviews, error: "" }),
  cancelRequest: api.cancelRequest,
}))

beforeEach(() => {
  api.mine = [held, withdrawn]
  api.reviews = []
  api.cancelRequest.mockClear()
})

describe("Approvals", () => {
  it("shows a request's full name and detail", async () => {
    render(<Approvals />)
    const labels = await screen.findAllByText(`apply Prompt default/${held.name}`)
    expect(labels).toHaveLength(2)
    for (const label of labels) {
      expect(label).toHaveClass("break-all")
      expect(label).not.toHaveClass("truncate")
    }
    expect(screen.getByText("cancelled by carol")).not.toHaveClass("truncate")
  })

  it("asks before withdrawing a request", async () => {
    render(<Approvals />)
    await userEvent.click(await screen.findByRole("button", { name: "Withdraw" }))
    const dialog = screen.getByRole("dialog")
    expect(within(dialog).getByText(/won't be applied/)).toBeInTheDocument()
    expect(api.cancelRequest).not.toHaveBeenCalled()

    await userEvent.click(within(dialog).getByRole("button", { name: "Keep it" }))
    expect(api.cancelRequest).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole("button", { name: "Withdraw" }))
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Withdraw" }))
    expect(api.cancelRequest).toHaveBeenCalledWith({}, "arq_1")
  })

  it("marks the user's own request to review, and leaves the decision to the policy", async () => {
    const other: ApprovalRequest = { ...held, id: "arq_2", name: "theirs", requesterSubject: "dave-sub", requesterUsername: "dave" }
    api.reviews = [
      { task: { id: "arq_1", status: "pending" }, change: held },
      { task: { id: "arq_2", status: "pending" }, change: other },
    ]
    render(<Approvals />)
    await userEvent.click(await screen.findByRole("button", { name: /To review/ }))
    expect(await screen.findByText("Your request")).toBeInTheDocument()
    expect(screen.getByText("by dave")).toBeInTheDocument()

    await userEvent.click(screen.getAllByRole("button", { name: "Review" })[0])
    const dialog = screen.getByRole("dialog")
    expect(within(dialog).getByText(/This is your own request/)).toBeInTheDocument()
    expect(within(dialog).getByRole("button", { name: "Approve" })).toBeEnabled()
  })
})
