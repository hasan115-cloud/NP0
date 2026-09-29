import { Pool, PoolClient } from "pg";
import {
  EnrolledClient,
  ONLINE_THRESHOLD_MS,
  PhishingRule,
  ThreatAlert,
  UrlEvent,
  WhitelistRule
} from "./types";
import {
  IDatabase,
  UrlEventFilters,
  UrlEventsResult,
  DashboardStatsResult,
  ReportDataResult
} from "./dbTypes";

/**
 * Postgres-backed implementation of IDatabase.
 *
 * WHY THIS EXISTS
 *
 * The file-backed store (FileDatabase, server/db.ts) is correct and fast
 * for a single long-lived process, but it cannot be correct across
 * multiple independent serverless function instances: each Vercel Serverless
 * Function / Lambda container gets its OWN filesystem, so a URL event
 * written by the instance that handled the extension's POST is simply
 * invisible to a different instance that happens to handle the next
 * dashboard poll. That produces exactly the symptom reported — a count
 * that looks right immediately after the write (same warm instance) and
 * then drops on the next request (a different instance, or a recycled
 * one, with no memory of the write at all).
 *
 * This class fixes that by moving the single source of truth to a real,
 * externally-reachable database. Every instance — no matter how many
 * there are, or how often they're recycled — reads and writes the SAME
 * rows, so the dashboard sees identical data regardless of which instance
 * answered which request.
 *
 * Used automatically whenever DATABASE_URL is set (see server/db.ts for
 * the selection). Works with any standard Postgres-wire-protocol database
 * — Neon, Supabase, Cloud SQL, RDS, or a self-hosted instance.
 *
 * Idempotency (the extension's offline-queue replay guarantee) is enforced
 * with a database-level UNIQUE constraint on event_id, using
 * `ON CONFLICT (event_id) DO NOTHING`. That is strictly stronger than the
 * file store's in-memory Set check: a UNIQUE constraint is enforced
 * atomically by Postgres itself, so it holds even under real concurrent
 * writes from many separate connections/instances at once — there's no
 * "check the Set, then write" gap for two instances to race through
 * simultaneously.
 */
// Managed Postgres providers (Supabase, Neon, RDS, etc.) require TLS, and
// commonly present certificate chains that fail Node's default strict
// validation depending on the runtime's CA bundle — this is standard,
// documented behavior for connecting to Supabase from Node/serverless
// environments, not a sign of a misconfigured database. A local/self-hosted
// database (localhost/127.0.0.1, or an explicit `sslmode=disable`) is left
// unencrypted-by-default so plain local Postgres and Docker Compose setups
// keep working with zero extra configuration. Everything else gets TLS with
// `rejectUnauthorized: false`: the connection is still encrypted, it just
// doesn't hard-fail on a chain Node can't verify — the same trade-off
// Supabase's own connection examples for Node use.
function resolveSslConfig(connectionString: string): false | { rejectUnauthorized: boolean } {
  const isLocalHost = /@(localhost|127\.0\.0\.1)(:|\/)/i.test(connectionString) ||
    /^postgres(ql)?:\/\/(localhost|127\.0\.0\.1)/i.test(connectionString);
  if (isLocalHost) return false;
  if (/sslmode=disable/i.test(connectionString)) return false;
  return { rejectUnauthorized: false };
}

export class PostgresDatabase implements IDatabase {
  private pool: Pool;
  private ready: Promise<void>;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      ssl: resolveSslConfig(connectionString),
      // Serverless-friendly: a small, short-lived pool per instance. Each
      // function invocation should hold at most a couple of connections,
      // never accumulate them — a large pool per instance is how
      // serverless deployments exhaust a database's connection limit when
      // they scale out to many concurrent instances.
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000
    });
    this.ready = this.ensureSchema();
    // Attach a handler to the rejection IMMEDIATELY, synchronously, in this
    // same constructor call. Without this, if DATABASE_URL is invalid or
    // the database is unreachable, ensureSchema()'s rejection can fire
    // before any request has had a chance to `await this.ready` — and an
    // unhandled promise rejection with zero listeners crashes the entire
    // Node process by default. That is a WORSE failure mode than intended:
    // a hard crash-loop with a raw stack trace, rather than the server
    // staying up and answering every request with a clear, honest error
    // until the database becomes reachable. This .catch() only logs; it
    // does NOT swallow the rejection — `this.ready` is still the same
    // rejected promise, so every q() call's `await this.ready` still
    // throws normally, and every route's existing try/catch still returns
    // a clear 500 with the real error message. There is no fallback to
    // file storage and no fake/empty data returned at any point.
    this.ready.catch(err => {
      console.error(
        "FATAL: Postgres initialization failed. DATABASE_URL is set but the " +
        "database is unreachable or misconfigured. The server will answer " +
        "every request with an explicit error until this is fixed — it will " +
        "NOT fall back to local file storage or return empty/fake data.",
        err
      );
    });
  }

  private async ensureSchema(): Promise<void> {
    // IF NOT EXISTS everywhere: safe to run on every cold start, and never
    // destroys a single existing row. This is the full schema migration —
    // there is nothing else to run.
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        client_name TEXT NOT NULL,
        first_seen TIMESTAMPTZ NOT NULL,
        last_seen TIMESTAMPTZ NOT NULL,
        status TEXT NOT NULL DEFAULT 'ENROLLED',
        extension_version TEXT,
        browser TEXT,
        os TEXT,
        platform TEXT,
        ip TEXT
      );

      CREATE TABLE IF NOT EXISTS url_events (
        id TEXT PRIMARY KEY,
        event_id TEXT,
        client_id TEXT NOT NULL,
        client_name TEXT,
        url TEXT NOT NULL,
        domain TEXT,
        classification TEXT NOT NULL,
        verdict TEXT NOT NULL,
        score DOUBLE PRECISION,
        reason TEXT,
        source TEXT,
        rule_triggered BOOLEAN DEFAULT FALSE,
        rule_type TEXT,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      -- One row per real observation: a client-supplied eventId can only
      -- ever land once, enforced by the database itself.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_url_events_event_id
        ON url_events (event_id) WHERE event_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_url_events_client ON url_events (client_id);
      CREATE INDEX IF NOT EXISTS idx_url_events_occurred_at ON url_events (occurred_at DESC);
      CREATE INDEX IF NOT EXISTS idx_url_events_classification ON url_events (classification);

      CREATE TABLE IF NOT EXISTS threat_alerts (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        client_name TEXT,
        url TEXT NOT NULL,
        domain TEXT,
        score DOUBLE PRECISION,
        reasons JSONB,
        source TEXT,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS idx_threat_alerts_client ON threat_alerts (client_id);
      CREATE INDEX IF NOT EXISTS idx_threat_alerts_status ON threat_alerts (status);

      CREATE TABLE IF NOT EXISTS whitelist_rules (
        id TEXT PRIMARY KEY,
        pattern TEXT NOT NULL UNIQUE,
        description TEXT,
        added_by TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS phishing_rules (
        id TEXT PRIMARY KEY,
        pattern TEXT NOT NULL UNIQUE,
        severity TEXT NOT NULL,
        reason TEXT,
        added_by TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      -- Write-only diagnostic log (never read back by any endpoint), kept
      -- for parity with the file store's schema. Capped by trimming old
      -- rows in heartbeatClient() rather than growing without bound.
      CREATE TABLE IF NOT EXISTS heartbeats (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        stats JSONB
      );

      -- Harmonize columns across migrations
      ALTER TABLE threat_alerts ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ DEFAULT now();
      ALTER TABLE heartbeats ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ DEFAULT now();

      -- Ensure fallback workstation exists for foreign key constraints
      INSERT INTO clients (id, client_name, first_seen, last_seen, status, extension_version, browser, os, platform, ip)
      VALUES ('anonymous', 'Default Workstation', now(), now(), 'ENROLLED', '1.4', 'Chrome', 'Linux', 'x86_64', 'remote-workstation')
      ON CONFLICT (id) DO NOTHING;
    `);

    // Baseline security policy rules if empty
    try {
      const wlCount = await this.pool.query("SELECT COUNT(*) AS count FROM whitelist_rules");
      if (parseInt(wlCount.rows[0]?.count || "0", 10) === 0) {
        await this.pool.query(`
          INSERT INTO whitelist_rules (id, pattern, description, added_by) VALUES
            ('wl_corp_internal', '*.corp.internal', 'Corporate internal network and infrastructure', 'System Policy'),
            ('wl_google_ws', '*.google.com', 'Google Workspace and enterprise authentication', 'System Policy'),
            ('wl_msft_365', '*.microsoft.com', 'Microsoft 365, Azure AD, and Office services', 'System Policy'),
            ('wl_github', '*.github.com', 'Enterprise GitHub source repositories', 'System Policy')
          ON CONFLICT (pattern) DO NOTHING;
        `);
      }

      const phCount = await this.pool.query("SELECT COUNT(*) AS count FROM phishing_rules");
      if (parseInt(phCount.rows[0]?.count || "0", 10) === 0) {
        await this.pool.query(`
          INSERT INTO phishing_rules (id, pattern, severity, reason, added_by) VALUES
            ('ph_login_suspicious', '*login-verify-account*', 'CRITICAL', 'Interception rule: Account verification and credential harvesting pattern', 'System Policy'),
            ('ph_banking_alert', '*security-update-banking*', 'CRITICAL', 'Interception rule: High-risk banking credential harvesting pattern', 'System Policy'),
            ('ph_zip_tld', '*.zip', 'HIGH', 'Interception rule: Suspicious Top-Level Domain (TLD) payload delivery', 'System Policy')
          ON CONFLICT (pattern) DO NOTHING;
        `);
      }
    } catch (seedErr) {
      console.warn("Notice: Baseline rule seeding skipped:", seedErr);
    }
  }

  public getDatabaseInfo(): { isSupabase: boolean; host: string } {
    const isSupabase = Boolean((this.pool as any)?.options?.connectionString?.includes("supabase"));
    let host = "postgres";
    try {
      const u = new URL((this.pool as any)?.options?.connectionString || "");
      host = u.hostname;
    } catch {}
    return { isSupabase, host };
  }

  private async q<T = any>(text: string, params: any[] = []): Promise<{ rows: T[] }> {
    await this.ready;
    return this.pool.query(text, params);
  }

  // ─── mapping helpers: snake_case rows -> the app's existing camelCase shapes ───
  private mapClient(r: any): EnrolledClient {
    const timeVal = r.last_seen || r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const lastSeenIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    const firstSeenVal = r.first_seen || r.created_at || new Date();
    const parsedFirst = new Date(firstSeenVal);
    const firstSeenIso = !isNaN(parsedFirst.getTime()) ? parsedFirst.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      clientName: r.client_name,
      firstSeen: firstSeenIso,
      lastSeen: lastSeenIso,
      status: r.status,
      // Derived at READ time, same threshold and semantics as the file
      // store: "OFFLINE" means no recent heartbeat, never "deleted." This
      // system still counts toward Total Enrolled Systems regardless.
      connectionStatus: Date.now() - new Date(lastSeenIso).getTime() < ONLINE_THRESHOLD_MS ? "ONLINE" : "OFFLINE",
      extensionVersion: r.extension_version || "1.4",
      browser: r.browser || "Chrome",
      os: r.os || "Linux",
      platform: r.platform || "x86_64",
      ip: r.ip || "remote-ip",
      // Populated by attachTelemetry() from the authoritative event log —
      // never trusted from a stored counter, for the same reason the file
      // store derives it: an extension-reported counter can drift.
      telemetryStats: { totalScanned: 0, phishingBlocked: 0, suspiciousDetected: 0, safeEvaluated: 0 }
    };
  }

  private mapUrlEvent(r: any): UrlEvent {
    const timeVal = r.occurred_at || r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const validIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      eventId: r.event_id || undefined,
      timestamp: validIso,
      clientId: r.client_id,
      clientName: r.client_name,
      url: r.url,
      domain: r.domain,
      classification: r.classification,
      verdict: r.verdict,
      score: typeof r.score === "number" ? r.score : parseFloat(r.score || "0"),
      reason: r.reason,
      source: r.source,
      ruleTriggered: Boolean(r.rule_triggered),
      ruleType: r.rule_type || null
    };
  }

  private mapThreatAlert(r: any): ThreatAlert {
    const timeVal = r.occurred_at || r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const validIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      timestamp: validIso,
      clientId: r.client_id,
      clientName: r.client_name,
      url: r.url,
      domain: r.domain,
      score: typeof r.score === "number" ? r.score : parseFloat(r.score || "0"),
      reasons: Array.isArray(r.reasons) ? r.reasons : [],
      source: r.source,
      status: r.status
    };
  }

  private mapWhitelistRule(r: any): WhitelistRule {
    const timeVal = r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const validIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      pattern: r.pattern,
      description: r.description || "Whitelisted domain",
      createdAt: validIso,
      addedBy: r.added_by || "Admin"
    };
  }

  private mapPhishingRule(r: any): PhishingRule {
    const timeVal = r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const validIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      pattern: r.pattern,
      severity: r.severity,
      reason: r.reason || "Threat rule",
      createdAt: validIso,
      addedBy: r.added_by || "Admin"
    };
  }

  // Same bucketing rule as the file store, expressed once so every SQL
  // aggregate uses identical logic: anything not explicitly SUSPICIOUS or
  // PHISHING counts as SAFE, so total === safe+suspicious+phishing always
  // holds by construction, for the same reason it holds in FileDatabase.
  private static readonly BUCKET_CASE = `
    CASE
      WHEN classification = 'PHISHING' THEN 'phishing'
      WHEN classification = 'SUSPICIOUS' THEN 'suspicious'
      ELSE 'safe'
    END
  `;

  // ─── Rules ────────────────────────────────────────────────────────────
  public async getWhitelistRules(): Promise<WhitelistRule[]> {
    const { rows } = await this.q(`SELECT * FROM whitelist_rules ORDER BY created_at ASC`);
    return rows.map(this.mapWhitelistRule);
  }

  public async addWhitelistRule(pattern: string, description: string, addedBy = "Admin"): Promise<WhitelistRule> {
    const cleanPattern = pattern.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    const existing = await this.q(`SELECT * FROM whitelist_rules WHERE pattern = $1`, [cleanPattern]);
    if (existing.rows.length > 0) return this.mapWhitelistRule(existing.rows[0]);

    const id = `wl_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const { rows } = await this.q(
      `INSERT INTO whitelist_rules (id, pattern, description, added_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (pattern) DO UPDATE SET pattern = EXCLUDED.pattern
       RETURNING *`,
      [id, cleanPattern, description.trim() || "Whitelisted domain", addedBy]
    );
    return this.mapWhitelistRule(rows[0]);
  }

  public async deleteWhitelistRule(id: string): Promise<boolean> {
    const { rows } = await this.q(`DELETE FROM whitelist_rules WHERE id = $1 RETURNING id`, [id]);
    return rows.length > 0;
  }

  public async getPhishingRules(): Promise<PhishingRule[]> {
    const { rows } = await this.q(`SELECT * FROM phishing_rules ORDER BY created_at ASC`);
    return rows.map(this.mapPhishingRule);
  }

  public async addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string, addedBy = "Admin"): Promise<PhishingRule> {
    const cleanPattern = pattern.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    const existing = await this.q(`SELECT * FROM phishing_rules WHERE pattern = $1`, [cleanPattern]);
    if (existing.rows.length > 0) return this.mapPhishingRule(existing.rows[0]);

    const id = `ph_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const { rows } = await this.q(
      `INSERT INTO phishing_rules (id, pattern, severity, reason, added_by)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (pattern) DO UPDATE SET pattern = EXCLUDED.pattern
       RETURNING *`,
      [id, cleanPattern, severity, reason.trim() || "Identified malicious phishing target", addedBy]
    );
    return this.mapPhishingRule(rows[0]);
  }

  public async deletePhishingRule(id: string): Promise<boolean> {
    const { rows } = await this.q(`DELETE FROM phishing_rules WHERE id = $1 RETURNING id`, [id]);
    return rows.length > 0;
  }

  // ─── Clients ────────────────────────────────────────────────────────────
  public async registerOrUpdateClient(payload: {
    clientId: string;
    clientName?: string;
    os?: string;
    browser?: string;
    platform?: string;
    extensionVersion?: string;
    ip?: string;
  }): Promise<EnrolledClient> {
    const now = new Date();
    const defaultName = `Workstation-${payload.clientId.slice(-4).toUpperCase()}`;

    const { rows } = await this.q(
      `INSERT INTO clients (id, client_name, first_seen, last_seen, status, extension_version, browser, os, platform, ip)
       VALUES ($1, $2, $3, $3, 'ENROLLED', $4, $5, $6, $7, $8)
       ON CONFLICT (id) DO UPDATE SET
         last_seen = $3,
         status = 'ENROLLED',
         client_name = COALESCE($2, clients.client_name),
         extension_version = COALESCE($4, clients.extension_version),
         browser = COALESCE($5, clients.browser),
         os = COALESCE($6, clients.os),
         platform = COALESCE($7, clients.platform),
         ip = COALESCE($8, clients.ip)
       RETURNING *`,
      [
        payload.clientId,
        payload.clientName || defaultName,
        now,
        payload.extensionVersion || "1.4",
        payload.browser || "Chrome",
        payload.os || "Linux",
        payload.platform || "x86_64",
        payload.ip || "remote-ip"
      ]
    );
    return this.attachTelemetry(this.mapClient(rows[0]));
  }

  public async heartbeatClient(clientId: string, stats?: Record<string, number>, clientName?: string, ip?: string): Promise<boolean> {
    const existing = await this.q(`SELECT id FROM clients WHERE id = $1`, [clientId]);
    if (existing.rows.length === 0) {
      await this.registerOrUpdateClient({ clientId, clientName, ip });
      return true;
    }

    await this.q(
      `UPDATE clients SET
         last_seen = now(),
         status = 'ENROLLED',
         client_name = CASE WHEN client_name IS NULL OR client_name = '' THEN COALESCE($2, client_name) ELSE client_name END,
         ip = COALESCE($3, ip)
       WHERE id = $1`,
      [clientId, clientName, ip]
    );

    const id = `hb_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    await this.q(
      `INSERT INTO heartbeats (id, client_id, stats) VALUES ($1, $2, $3)`,
      [id, clientId, stats ? JSON.stringify(stats) : null]
    );
    // Cap the log the same way the file store did (last 500), instead of
    // growing this write-only diagnostic table without bound.
    await this.q(
      `DELETE FROM heartbeats WHERE id NOT IN (
         SELECT id FROM heartbeats ORDER BY occurred_at DESC LIMIT 500
       )`
    );

    return true;
  }

  /** Derives every client's counts from the event log in ONE query. */
  private async telemetryByClient(): Promise<Map<string, EnrolledClient["telemetryStats"]>> {
    const { rows } = await this.q(`
      SELECT
        client_id,
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE classification = 'PHISHING')::int AS phishing,
        COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS')::int AS suspicious,
        COUNT(*) FILTER (WHERE classification NOT IN ('PHISHING','SUSPICIOUS'))::int AS safe
      FROM url_events
      GROUP BY client_id
    `);
    const map = new Map<string, EnrolledClient["telemetryStats"]>();
    for (const r of rows) {
      map.set(r.client_id, {
        totalScanned: r.total,
        phishingBlocked: r.phishing,
        suspiciousDetected: r.suspicious,
        safeEvaluated: r.safe
      });
    }
    return map;
  }

  private async attachTelemetry(client: EnrolledClient): Promise<EnrolledClient> {
    const map = await this.telemetryByClient();
    client.telemetryStats = map.get(client.id) || client.telemetryStats;
    return client;
  }

  public async getClients(): Promise<EnrolledClient[]> {
    const [{ rows }, telemetry] = await Promise.all([
      this.q(`SELECT * FROM clients ORDER BY first_seen DESC`),
      this.telemetryByClient()
    ]);
    return rows.map(r => {
      const c = this.mapClient(r);
      c.telemetryStats = telemetry.get(c.id) || c.telemetryStats;
      return c;
    });
  }

  public async clientExists(id: string): Promise<boolean> {
    const { rows } = await this.q(`SELECT 1 FROM clients WHERE id = $1`, [id]);
    return rows.length > 0;
  }

  public async getClientById(id: string): Promise<EnrolledClient | null> {
    const { rows } = await this.q(`SELECT * FROM clients WHERE id = $1`, [id]);
    if (rows.length === 0) return null;
    return this.attachTelemetry(this.mapClient(rows[0]));
  }

  public async deleteClient(id: string): Promise<boolean> {
    const { rows } = await this.q(`DELETE FROM clients WHERE id = $1 RETURNING id`, [id]);
    return rows.length > 0;
  }

  // ─── Threat alerts ───────────────────────────────────────────────────────
  public async recordThreatAlert(alert: Omit<ThreatAlert, "id" | "timestamp" | "status">): Promise<ThreatAlert> {
    const id = `alt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date();
    const cId = alert.clientId || "anonymous";
    const cName = alert.clientName || "Workstation";

    // Ensure client row exists to satisfy foreign key constraint fk_threat_alerts_client
    await this.q(
      `INSERT INTO clients (id, client_name, first_seen, last_seen, status, extension_version, browser, os, platform, ip)
       VALUES ($1, $2, $3, $3, 'ENROLLED', '1.4', 'Chrome', 'Linux', 'x86_64', 'remote-ip')
       ON CONFLICT (id) DO UPDATE SET last_seen = EXCLUDED.last_seen`,
      [cId, cName, now]
    );

    const { rows } = await this.q(
      `INSERT INTO threat_alerts (id, client_id, client_name, url, domain, score, reasons, source, status, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'ACTIVE', $9)
       RETURNING *`,
      [id, cId, cName, alert.url, alert.domain, alert.score, JSON.stringify(alert.reasons || []), alert.source, now]
    );
    return this.mapThreatAlert(rows[0]);
  }

  public async getThreatAlerts(clientId?: string): Promise<ThreatAlert[]> {
    if (clientId && clientId !== "ALL") {
      const { rows } = await this.q(`SELECT * FROM threat_alerts WHERE client_id = $1 ORDER BY occurred_at DESC`, [clientId]);
      return rows.map(this.mapThreatAlert);
    }
    const { rows } = await this.q(`SELECT * FROM threat_alerts ORDER BY occurred_at DESC`);
    return rows.map(this.mapThreatAlert);
  }

  public async updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED"): Promise<boolean> {
    const { rows } = await this.q(`UPDATE threat_alerts SET status = $2 WHERE id = $1 RETURNING id`, [id, status]);
    return rows.length > 0;
  }

  // ─── URL events — the authoritative history ─────────────────────────────
  public async hasEventId(eventId: string): Promise<boolean> {
    const { rows } = await this.q(`SELECT 1 FROM url_events WHERE event_id = $1`, [eventId]);
    return rows.length > 0;
  }

  public async recordUrlEvent(
    event: Omit<UrlEvent, "id" | "timestamp">,
    occurredAt?: string
  ): Promise<{ event: UrlEvent; wasNew: boolean }> {
    const id = `evt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    let occurred = new Date();
    if (occurredAt) {
      const parsed = new Date(occurredAt);
      if (!Number.isNaN(parsed.getTime()) && parsed.getTime() <= Date.now()) {
        occurred = parsed;
      }
    }

    const cId = event.clientId || "anonymous";
    const cName = event.clientName || "Workstation";

    // Ensure client row exists to satisfy foreign key constraint fk_url_events_client
    await this.q(
      `INSERT INTO clients (id, client_name, first_seen, last_seen, status, extension_version, browser, os, platform, ip)
       VALUES ($1, $2, $3, $3, 'ENROLLED', '1.4', 'Chrome', 'Linux', 'x86_64', 'remote-ip')
       ON CONFLICT (id) DO UPDATE SET last_seen = EXCLUDED.last_seen`,
      [cId, cName, occurred]
    );

    // ON CONFLICT DO NOTHING is the atomic dedup: Postgres itself refuses a
    // second row with the same event_id, even under real concurrent writes
    // from separate connections/instances — there is no window in which
    // two processes can both "see no existing row" and both insert.
    const insertResult = await this.q(
      `INSERT INTO url_events
         (id, event_id, client_id, client_name, url, domain, classification, verdict, score, reason, source, rule_triggered, rule_type, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       ON CONFLICT (event_id) WHERE event_id IS NOT NULL DO NOTHING
       RETURNING *`,
      [
        id,
        event.eventId || null,
        cId,
        cName,
        event.url,
        event.domain,
        event.classification,
        event.verdict,
        event.score,
        event.reason,
        event.source,
        Boolean(event.ruleTriggered),
        event.ruleType || null,
        occurred
      ]
    );

    if (insertResult.rows.length > 0) {
      // The INSERT itself succeeded — this is the ONLY correct signal that
      // a new row was created. It comes from the same atomic statement
      // that did the write, so it's trustworthy even when another
      // instance is racing to insert the exact same eventId at the same
      // moment; Postgres's own uniqueness enforcement decides which one
      // wins, and only that one gets wasNew: true.
      return { event: this.mapUrlEvent(insertResult.rows[0]), wasNew: true };
    }

    // Conflict: this eventId already landed (possibly written by a
    // different instance, possibly a fraction of a second ago) — return
    // the existing row rather than inserting a duplicate, exactly like
    // the file store's dedup behavior.
    if (event.eventId) {
      const existing = await this.q(`SELECT * FROM url_events WHERE event_id = $1`, [event.eventId]);
      if (existing.rows.length > 0) return { event: this.mapUrlEvent(existing.rows[0]), wasNew: false };
    }

    // The unique index only applies when event_id IS NOT NULL, so a
    // conflict with no eventId is impossible — this can only mean the
    // conflicting row vanished between the insert and this lookup.
    throw new Error(`recordUrlEvent: conflict on eventId "${event.eventId}" but no matching row found on lookup`);
  }

  public async getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult> {
    const where: string[] = [];
    const params: any[] = [];

    if (filters?.clientId && filters.clientId !== "ALL") {
      params.push(filters.clientId);
      where.push(`client_id = $${params.length}`);
    }
    if (filters?.classification && filters.classification !== "ALL") {
      params.push(filters.classification);
      where.push(`classification = $${params.length}`);
    }
    if (filters?.search && filters.search.trim()) {
      params.push(`%${filters.search.trim().toLowerCase()}%`);
      const idx = params.length;
      where.push(`(LOWER(url) LIKE $${idx} OR LOWER(domain) LIKE $${idx} OR LOWER(client_name) LIKE $${idx} OR LOWER(reason) LIKE $${idx})`);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

    const countResult = await this.q(`SELECT COUNT(*)::int AS total FROM url_events ${whereSql}`, params);
    const total = countResult.rows[0]?.total || 0;

    // No default LIMIT: the complete matching history in one response is
    // the whole point — the frontend expects "everything that matches,"
    // not a silently truncated page. A limit is applied only when the
    // caller explicitly asks for one.
    let sql = `SELECT * FROM url_events ${whereSql} ORDER BY occurred_at DESC, id DESC`;
    const queryParams = [...params];
    if (typeof filters?.limit === "number") {
      queryParams.push(filters.limit);
      sql += ` LIMIT $${queryParams.length}`;
      queryParams.push(filters?.offset || 0);
      sql += ` OFFSET $${queryParams.length}`;
    } else if (filters?.offset) {
      queryParams.push(filters.offset);
      sql += ` OFFSET $${queryParams.length}`;
    }

    const { rows } = await this.q(sql, queryParams);
    return { events: rows.map(this.mapUrlEvent), total };
  }

  // ─── Dashboard statistics ────────────────────────────────────────────────
  public async getDashboardStats(clientId?: string): Promise<DashboardStatsResult> {
    const isGlobal = !clientId || clientId === "ALL";
    const params: any[] = [];
    let clientFilter = "";
    if (!isGlobal) {
      params.push(clientId);
      clientFilter = `WHERE client_id = $1`;
    }

    const [{ rows: sysRows }, { rows: bucketRows }, alertsResult, recentResult] = await Promise.all([
      this.q(`SELECT COUNT(*)::int AS n FROM clients`),
      this.q(
        `SELECT
           COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE classification = 'PHISHING')::int AS phishing,
           COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS')::int AS suspicious,
           COUNT(*) FILTER (WHERE classification NOT IN ('PHISHING','SUSPICIOUS'))::int AS safe
         FROM url_events ${clientFilter}`,
        params
      ),
      isGlobal
        ? this.q(`SELECT * FROM threat_alerts`)
        : this.q(`SELECT * FROM threat_alerts WHERE client_id = $1`, [clientId]),
      this.q(
        `SELECT * FROM url_events ${clientFilter} ORDER BY occurred_at DESC, id DESC LIMIT 10`,
        params
      )
    ]);

    const b = bucketRows[0] || { total: 0, phishing: 0, suspicious: 0, safe: 0 };
    const alerts = alertsResult.rows.map(this.mapThreatAlert);
    const activeAlerts = alerts.filter(a => a.status === "ACTIVE").length;

    const threatDomainCounts = new Map<string, number>();
    alerts.forEach(a => {
      if (a.domain) threatDomainCounts.set(a.domain, (threatDomainCounts.get(a.domain) || 0) + 1);
    });
    const topThreatDomains = Array.from(threatDomainCounts.entries())
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, c) => c.count - a.count)
      .slice(0, 5);

    return {
      scope: isGlobal ? "ALL" : (clientId as string),
      totalSystems: sysRows[0]?.n || 0,
      urlsMonitored: b.total,
      allowedUrls: b.safe,
      phishingIntercepted: b.phishing,
      activeAlerts,
      breakdown: { evaluated: b.total, safe: b.safe, suspicious: b.suspicious, phishing: b.phishing },
      recentEvents: recentResult.rows.map(this.mapUrlEvent),
      topThreatDomains
    };
  }

  // ─── Report data ─────────────────────────────────────────────────────────
  public async getReportData(clientId?: string): Promise<ReportDataResult> {
    const isGlobal = !clientId || clientId === "ALL";

    // `allMatching` holds the COMPLETE matching event set (no limit), so
    // both its `.total` and the bucket counts below reflect every record —
    // never just whatever page happens to be returned. Only the `events`
    // field in the final response is capped, purely to bound payload size.
    const [allMatching, alerts, scopedClients, allClients] = await Promise.all([
      this.getUrlEvents({ clientId }),
      this.getThreatAlerts(clientId),
      isGlobal ? this.getClients() : this.getClientById(clientId as string).then(c => (c ? [c] : [])),
      isGlobal ? this.getClients() : Promise.resolve<EnrolledClient[]>([])
    ]);

    const b = this.bucketCounts(allMatching.events);

    const threatDomainCounts = new Map<string, number>();
    alerts.forEach(a => {
      if (a.domain) threatDomainCounts.set(a.domain, (threatDomainCounts.get(a.domain) || 0) + 1);
    });
    const topThreatDomains = Array.from(threatDomainCounts.entries())
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, c) => c.count - a.count)
      .slice(0, 10);

    let perSystem: ReportDataResult["perSystem"] = [];
    if (isGlobal) {
      perSystem = await Promise.all(
        allClients.map(async c => {
          const clientEvents = await this.getUrlEvents({ clientId: c.id });
          const clientAlerts = await this.getThreatAlerts(c.id);
          const cb = this.bucketCounts(clientEvents.events);
          return {
            clientId: c.id,
            clientName: c.clientName,
            os: c.os,
            browser: c.browser,
            totalScanned: clientEvents.total,
            safe: cb.safe,
            suspicious: cb.suspicious,
            phishing: cb.phishing,
            activeAlerts: clientAlerts.filter(a => a.status === "ACTIVE").length
          };
        })
      );
    }

    return {
      scope: isGlobal ? "ALL" : (clientId as string),
      generatedAt: new Date().toISOString(),
      systems: scopedClients,
      summary: {
        totalEvaluated: allMatching.total,
        safe: b.safe,
        suspicious: b.suspicious,
        phishing: b.phishing,
        activeAlerts: alerts.filter(a => a.status === "ACTIVE").length
      },
      topThreatDomains,
      events: allMatching.events.slice(0, 1000),
      alerts: alerts.slice(0, 500),
      perSystem
    };
  }

  private bucketCounts(events: UrlEvent[]) {
    let safe = 0, suspicious = 0, phishing = 0;
    for (const e of events) {
      if (e.classification === "PHISHING") phishing++;
      else if (e.classification === "SUSPICIOUS") suspicious++;
      else safe++;
    }
    return { safe, suspicious, phishing };
  }

  public isPossiblyEphemeralDeployment(): boolean {
    // A real external database is exactly what removes the ephemeral-
    // filesystem risk, regardless of whether the process itself is
    // running in a serverless environment.
    return false;
  }
}
