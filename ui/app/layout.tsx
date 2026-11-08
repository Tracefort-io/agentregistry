import type { Metadata } from "next"
import { Plus_Jakarta_Sans } from "next/font/google"
import { Navigation } from "@/components/navigation"
import { Footer } from "@/components/footer"
import { ThemeProvider } from "@/components/theme-provider"
import { CatalogNavProvider } from "@/lib/catalog-nav"
import { Toaster } from "@/components/ui/sonner"
import "./globals.css"

const jakarta = Plus_Jakarta_Sans({
  subsets: ["latin"],
  variable: "--font-jakarta",
})

export const metadata: Metadata = {
  title: "Tracefort",
  description: "Admin interface for managing Tracefort",
  icons: {
    icon: "/icon.svg",
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${jakarta.variable} font-sans`}>
        <ThemeProvider>
          <CatalogNavProvider>
            <div className="min-h-screen flex flex-col md:flex-row">
              <Navigation />
              <div className="flex-1 min-w-0 flex flex-col">
                <div className="flex-1">
                  {children}
                </div>
                <Footer />
              </div>
            </div>
          </CatalogNavProvider>
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  )
}
