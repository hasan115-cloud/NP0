import { createClient, SupabaseClient } from "@supabase/supabase-js";

export interface SupabaseConfig {
  connectionString?: string;
  projectRef: string;
  host: string;
  port: string;
  supabaseUrl: string;
  apiKey?: string;
}

export function isApiKey(str?: string): boolean {
  if (!str) return false;
  const trimmed = str.trim();
  return (
    trimmed.startsWith("sb_publishable_") ||
    trimmed.startsWith("sb_secret_") ||
    trimmed.startsWith("eyJ") // JWT
  );
}

export function isPostgresUrl(str?: string): boolean {
  if (!str) return false;
  const trimmed = str.trim().toLowerCase();
  return trimmed.startsWith("postgres://") || trimmed.startsWith("postgresql://");
}

export function getResolvedSupabaseKey(): string | null {
  const directCandidate =
    process.env.SUPABASE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (directCandidate && directCandidate.trim()) {
    return directCandidate.trim();
  }

  // Check if DATABASE_URL was mistakenly set to an API key instead of a connection string
  const dbUrl = process.env.DATABASE_URL || process.env.SUPABASE_DATABASE_URL || process.env.POSTGRES_URL;
  if (dbUrl && isApiKey(dbUrl)) {
    return dbUrl.trim();
  }

  return "sb_publishable_n_b7T_iYLfS3GIIKuuKmtA_lKe1vV-3";
}

export function parseSupabaseConnection(connStr?: string): SupabaseConfig | null {
  const raw =
    connStr ||
    process.env.DATABASE_URL ||
    process.env.SUPABASE_DATABASE_URL ||
    process.env.POSTGRES_URL;

  const resolvedKey = getResolvedSupabaseKey();

  // If raw is an API key, return config with that key
  if (raw && isApiKey(raw)) {
    const supabaseUrl =
      process.env.SUPABASE_URL ||
      process.env.NEXT_PUBLIC_SUPABASE_URL ||
      "https://tfcxufkprwywemxyyeqd.supabase.co";
    return {
      projectRef: "tfcxufkprwywemxyyeqd",
      host: "tfcxufkprwywemxyyeqd.supabase.co",
      port: "443",
      supabaseUrl,
      apiKey: raw.trim(),
    };
  }

  if (!raw || !isPostgresUrl(raw)) {
    if (resolvedKey) {
      const supabaseUrl =
        process.env.SUPABASE_URL ||
        process.env.NEXT_PUBLIC_SUPABASE_URL ||
        "https://tfcxufkprwywemxyyeqd.supabase.co";
      return {
        projectRef: "tfcxufkprwywemxyyeqd",
        host: "tfcxufkprwywemxyyeqd.supabase.co",
        port: "443",
        supabaseUrl,
        apiKey: resolvedKey,
      };
    }
    return null;
  }

  try {
    const parsed = new URL(raw);
    let projectRef = "";
    if (parsed.username && parsed.username.includes(".")) {
      projectRef = parsed.username.split(".")[1] || "";
    } else if (parsed.hostname.includes(".")) {
      const parts = parsed.hostname.split(".");
      if (parts[0] === "db" && parts[2] === "supabase") {
        projectRef = parts[1];
      }
    }
    if (!projectRef) projectRef = "tfcxufkprwywemxyyeqd";

    const host = parsed.hostname;
    const port = parsed.port || "6543";
    const supabaseUrl = projectRef
      ? `https://${projectRef}.supabase.co`
      : process.env.SUPABASE_URL ||
        process.env.NEXT_PUBLIC_SUPABASE_URL ||
        `https://${host}`;

    return {
      connectionString: raw,
      projectRef,
      host,
      port,
      supabaseUrl,
      apiKey: resolvedKey || undefined,
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
    config?.supabaseUrl ||
    "https://tfcxufkprwywemxyyeqd.supabase.co";

  const supabaseKey = getResolvedSupabaseKey() || config?.apiKey;

  if (supabaseUrl && supabaseKey) {
    return createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false },
    });
  }
  return null;
}
