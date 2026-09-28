import { createClient, SupabaseClient } from "@supabase/supabase-js";

export interface SupabaseConfig {
  connectionString: string;
  projectRef: string;
  host: string;
  port: string;
  supabaseUrl: string;
}

export function parseSupabaseConnection(connStr?: string): SupabaseConfig | null {
  const url =
    connStr ||
    process.env.DATABASE_URL ||
    process.env.SUPABASE_DATABASE_URL ||
    process.env.POSTGRES_URL;
  if (!url) return null;

  try {
    const parsed = new URL(url);
    let projectRef = "";
    if (parsed.username && parsed.username.includes(".")) {
      projectRef = parsed.username.split(".")[1] || "";
    } else if (parsed.hostname.includes(".")) {
      const parts = parsed.hostname.split(".");
      if (parts[0] === "db" && parts[2] === "supabase") {
        projectRef = parts[1];
      }
    }

    const host = parsed.hostname;
    const port = parsed.port || "6543";
    const supabaseUrl = projectRef
      ? `https://${projectRef}.supabase.co`
      : process.env.SUPABASE_URL ||
        process.env.NEXT_PUBLIC_SUPABASE_URL ||
        `https://${host}`;

    return {
      connectionString: url,
      projectRef,
      host,
      port,
      supabaseUrl,
    };
  } catch {
    return null;
  }
}

/**
 * Returns an initialized Supabase JS client when standard REST API keys
 * are available, or null when using the direct connection string.
 */
export function getSupabaseClient(): SupabaseClient | null {
  const config = parseSupabaseConnection();
  const supabaseUrl =
    process.env.SUPABASE_URL ||
    process.env.NEXT_PUBLIC_SUPABASE_URL ||
    config?.supabaseUrl;
  const supabaseKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (supabaseUrl && supabaseKey) {
    return createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false },
    });
  }
  return null;
}
