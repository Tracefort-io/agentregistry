"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useTheme } from "next-themes"
import { useState, useSyncExternalStore } from "react"
import { Cpu, KeyRound, LogOut, Menu, Moon, Puzzle, Rocket, ScrollText, Server, Sun, UserRound } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet"
import { CATALOG_SECTIONS, useCatalogNav } from "@/lib/catalog-nav"
import { useAuth } from "@/lib/auth"
import { useIsAdmin } from "@/lib/permissions"

// Platform resources, managed on their own pages.
const PLATFORM_LINKS = [
  { href: "/runtimes", label: "Runtimes", icon: <Server className="h-3.5 w-3.5" /> },
  { href: "/models", label: "Models", icon: <Cpu className="h-3.5 w-3.5" /> },
  { href: "/plugins", label: "Plugins", icon: <Puzzle className="h-3.5 w-3.5" /> },
  { href: "/secrets", label: "Secrets", icon: <KeyRound className="h-3.5 w-3.5" /> },
]

// Shown to registry admins only; the registry refuses everyone else anyway.
const ADMIN_LINKS = [
  { href: "/audit", label: "Audit log", icon: <ScrollText className="h-3.5 w-3.5" /> },
]

const itemClass = (active: boolean) =>
  `group flex items-center gap-2.5 rounded-md px-3 py-2 text-[15px] font-medium transition-colors ${
    active
      ? "bg-primary/10 text-foreground"
      : "text-muted-foreground hover:bg-muted hover:text-foreground"
  }`

const iconClass = (active: boolean) =>
  `h-4 w-4 flex items-center justify-center transition-colors ${
    active ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
  }`

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname()
  const { theme, setTheme } = useTheme()
  const mounted = useSyncExternalStore(() => () => {}, () => true, () => false)
  const { activeTab, setActiveTab, counts } = useCatalogNav()
  const { user, signOut } = useAuth()
  const isAdmin = useIsAdmin()
  const platformLinks = isAdmin ? [...PLATFORM_LINKS, ...ADMIN_LINKS] : PLATFORM_LINKS
  const userName = user?.profile.preferred_username || user?.profile.name || user?.profile.email

  return (
    <div className="flex h-full flex-col">
      <Link href="/" onClick={onNavigate} className="px-3 py-4">
        <span className="text-xl font-bold tracking-tight text-foreground">Tracefort</span>
      </Link>

      <nav className="flex-1 space-y-6 px-2 py-2">
        <div>
          <p className="px-3 pb-2 text-xs font-semibold text-muted-foreground">AI Registry</p>
          <div className="space-y-0.5">
            {CATALOG_SECTIONS.map(({ key, label, icon }) => {
              const active = pathname === "/" && activeTab === key
              return (
                <Link
                  key={key}
                  href="/"
                  onClick={() => {
                    setActiveTab(key)
                    onNavigate?.()
                  }}
                  className={itemClass(active)}
                >
                  <span className={iconClass(active)}>{icon}</span>
                  <span className="flex-1">{label}</span>
                  {counts && (
                    <span className={`text-[13px] tabular-nums px-1.5 py-0.5 rounded-full transition-colors ${
                      active ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"
                    }`}>
                      {counts[key]}
                    </span>
                  )}
                </Link>
              )
            })}
          </div>
        </div>

        <Link href="/deployed" onClick={onNavigate} className={itemClass(pathname.startsWith("/deployed"))}>
          <span className={iconClass(pathname.startsWith("/deployed"))}>
            <Rocket className="h-3.5 w-3.5" />
          </span>
          Deployed
        </Link>

        <div>
          <p className="px-3 pb-2 text-xs font-semibold text-muted-foreground">Platform</p>
          <div className="space-y-0.5">
            {platformLinks.map(({ href, label, icon }) => {
              const active = pathname.startsWith(href)
              return (
                <Link key={href} href={href} onClick={onNavigate} className={itemClass(active)}>
                  <span className={iconClass(active)}>{icon}</span>
                  {label}
                </Link>
              )
            })}
          </div>
        </div>
      </nav>

      <div className="border-t px-2 py-3 space-y-1">
        {user && (
          <>
            <div className="flex items-center gap-2.5 px-3 py-2 text-sm text-foreground" title={user.profile.sub}>
              <UserRound className="h-4 w-4 text-muted-foreground" />
              <span className="truncate">{userName || "Signed in"}</span>
            </div>
            <Button
              variant="ghost"
              className="w-full justify-start gap-2.5 px-3 text-muted-foreground hover:text-foreground"
              onClick={signOut}
            >
              <LogOut className="h-4 w-4" />
              Sign out
            </Button>
          </>
        )}
        {mounted && (
          <Button
            variant="ghost"
            className="w-full justify-start gap-2.5 px-3 text-muted-foreground hover:text-foreground"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </Button>
        )}
      </div>
    </div>
  )
}

export function Navigation() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <>
      {/* Narrow screens: top bar with a menu button that slides the sidebar out */}
      <header className="md:hidden sticky top-0 z-50 flex h-14 items-center gap-3 border-b bg-background px-4">
        <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setMobileOpen(true)} title="Open menu">
          <Menu className="h-4 w-4" />
        </Button>
        <span className="text-lg font-bold tracking-tight text-foreground">Tracefort</span>
      </header>
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="w-60 p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarContent onNavigate={() => setMobileOpen(false)} />
        </SheetContent>
      </Sheet>

      {/* Wide screens: fixed left sidebar */}
      <aside className="hidden md:block sticky top-0 h-screen w-60 shrink-0 border-r bg-background">
        <SidebarContent />
      </aside>
    </>
  )
}
