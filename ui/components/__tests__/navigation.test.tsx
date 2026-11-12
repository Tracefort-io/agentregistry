import { render, screen } from "@testing-library/react"
import { describe, it, expect, vi, beforeEach } from "vitest"

let isAdmin = false

vi.mock("next/navigation", () => ({ usePathname: () => "/" }))
vi.mock("next-themes", () => ({ useTheme: () => ({ theme: "light", setTheme: vi.fn() }) }))
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: null, signOut: vi.fn() }) }))
vi.mock("@/lib/catalog-nav", () => ({
  CATALOG_SECTIONS: [],
  useCatalogNav: () => ({ activeTab: "", setActiveTab: vi.fn(), counts: null }),
}))
vi.mock("@/lib/permissions", () => ({ useIsAdmin: () => isAdmin }))

import { Navigation } from "../navigation"

describe("Navigation", () => {
  beforeEach(() => {
    isAdmin = false
  })

  it("shows the audit log to registry admins", () => {
    isAdmin = true
    render(<Navigation />)
    expect(screen.getAllByRole("link", { name: /Audit log/ })[0]).toHaveAttribute("href", "/audit")
  })

  it("hides the audit log from everyone else", () => {
    render(<Navigation />)
    expect(screen.queryByRole("link", { name: /Audit log/ })).toBeNull()
    expect(screen.getAllByRole("link", { name: /Secrets/ }).length).toBeGreaterThan(0)
  })
})
