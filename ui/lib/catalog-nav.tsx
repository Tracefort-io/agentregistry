"use client"

import { createContext, useContext, useState } from "react"
import { Zap, Bot, FileText } from "lucide-react"
import MCPIcon from "@/components/icons/mcp"

export type TabKey = "servers" | "skills" | "agents" | "prompts"

export const CATALOG_SECTIONS: { key: TabKey; label: string; icon: React.ReactNode }[] = [
  { key: "servers", label: "MCP Servers", icon: <MCPIcon /> },
  { key: "skills", label: "Skills", icon: <Zap className="h-3.5 w-3.5" /> },
  { key: "agents", label: "Agents", icon: <Bot className="h-3.5 w-3.5" /> },
  { key: "prompts", label: "Prompts", icon: <FileText className="h-3.5 w-3.5" /> },
]

// Counts are published by the AI Registry page once it has loaded data; null
// until then, so the sidebar can hide them rather than show zeros.
type Counts = Record<TabKey, number> | null

interface CatalogNavState {
  activeTab: TabKey
  setActiveTab: (tab: TabKey) => void
  counts: Counts
  setCounts: (counts: Counts) => void
}

const CatalogNavContext = createContext<CatalogNavState | null>(null)

// CatalogNavProvider shares the selected catalog section and its counts
// between the sidebar and the AI Registry page.
export function CatalogNavProvider({ children }: { children: React.ReactNode }) {
  const [activeTab, setActiveTab] = useState<TabKey>("servers")
  const [counts, setCounts] = useState<Counts>(null)
  return (
    <CatalogNavContext.Provider value={{ activeTab, setActiveTab, counts, setCounts }}>
      {children}
    </CatalogNavContext.Provider>
  )
}

export function useCatalogNav(): CatalogNavState {
  const ctx = useContext(CatalogNavContext)
  if (!ctx) {
    throw new Error("useCatalogNav must be used within CatalogNavProvider")
  }
  return ctx
}
