import Link from "next/link";
import { redirect } from "next/navigation";

import SignOutButton from "@/components/auth/sign-out-button";
import { createClient } from "@/lib/supabase/server";

export default async function ProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <header className="border-b border-zinc-800 bg-zinc-900/80">
        <div className="mx-auto flex w-full max-w-5xl items-center justify-between gap-4 px-6 py-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-cyan-400">VibePenTester</p>
            <h1 className="text-sm font-semibold">Authenticated App</h1>
          </div>

          <nav className="flex items-center gap-4 text-sm">
            <Link href="/app/scans" className="text-zinc-200 hover:text-cyan-300">
              Scans
            </Link>
          </nav>

          <div className="flex items-center gap-3">
            <span className="hidden text-xs text-zinc-400 sm:inline">{user.email}</span>
            <SignOutButton />
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl px-6 py-8">{children}</main>
    </div>
  );
}
