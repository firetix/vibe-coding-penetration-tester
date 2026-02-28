import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";

import { getSupabasePublicConfig } from "@/lib/env";

let browserClient: SupabaseClient | undefined;

export function createClient() {
  if (browserClient) {
    return browserClient;
  }

  const { supabaseUrl, supabaseAnonKey } = getSupabasePublicConfig();

  browserClient = createBrowserClient(supabaseUrl, supabaseAnonKey);
  return browserClient;
}
