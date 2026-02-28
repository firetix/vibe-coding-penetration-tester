type RequiredPublicEnvVar =
  | "NEXT_PUBLIC_SUPABASE_URL"
  | "NEXT_PUBLIC_SUPABASE_ANON_KEY"
  | "NEXT_PUBLIC_API_BASE_URL";

function requirePublicEnv(name: RequiredPublicEnvVar): string {
  const value = process.env[name];

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
