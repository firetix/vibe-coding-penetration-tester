type RequiredPublicEnvVar =
  | "NEXT_PUBLIC_SUPABASE_URL"
  | "NEXT_PUBLIC_SUPABASE_ANON_KEY"
  | "NEXT_PUBLIC_API_BASE_URL";

// Next.js client bundles only reliably expose direct env references.
// Keep these lookups explicit so the variables are available in browser code.
const publicEnv = {
  NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
  NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL,
} as const;

function requirePublicEnv(name: RequiredPublicEnvVar): string {
  const value = publicEnv[name];

  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
}

export function getSupabasePublicConfig() {
  return {
    supabaseUrl: requirePublicEnv("NEXT_PUBLIC_SUPABASE_URL"),
    supabaseAnonKey: requirePublicEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY"),
  };
}

export function getApiBaseUrl() {
  return requirePublicEnv("NEXT_PUBLIC_API_BASE_URL").replace(/\/$/, "");
}
