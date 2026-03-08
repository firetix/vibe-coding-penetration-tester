import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-3xl flex-col justify-center gap-6 px-6 py-16">
      <span className="inline-flex w-fit rounded-full border border-cyan-400/40 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-cyan-500">
        VibePenTester Frontend
      </span>
      <h1 className="text-4xl font-semibold tracking-tight">Supabase + Railway integration baseline</h1>
      <p className="max-w-2xl text-sm text-zinc-600 dark:text-zinc-300">
        This Next.js app is the Vercel-deployed frontend. It uses Supabase Auth for
        login/session management and calls the Railway API for scan creation + listing.
      </p>

      <div className="flex flex-wrap gap-3">
        <Link
          href="/login"
          className="rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500"
        >
          Login
        </Link>
        <Link
          href="/signup"
          className="rounded-md border border-zinc-300 px-4 py-2 text-sm font-medium hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-900"
        >
          Sign up
        </Link>
        <Link
          href="/app/scans"
          className="rounded-md border border-zinc-300 px-4 py-2 text-sm font-medium hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-900"
        >
          Go to app
        </Link>
      </div>
    </main>
  );
}
