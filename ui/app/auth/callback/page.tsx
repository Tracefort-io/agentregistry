// The identity provider returns here after sign-in. AuthProvider finishes the
// sign-in and replaces this URL with the page the user started from, so this
// page only shows while that happens.
export default function AuthCallbackPage() {
  return (
    <main className="flex min-h-[50vh] items-center justify-center">
      <p className="text-sm text-muted-foreground">Signing in…</p>
    </main>
  )
}
