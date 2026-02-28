import { redirect } from "next/navigation";

import { createClient } from "@/lib/supabase/server";

import { LoginForm } from "./login-form";

export default async function LoginPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) {
    redirect("/app");
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-6 py-16">
      <h1 className="text-3xl font-semibold tracking-tight">Login</h1>
      <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-300">
        Access your VibePenTester workspace with Supabase Auth.
      </p>
      <LoginForm />
    </main>
  );
}
