import fs from "fs";
import path from "path";
import {
  DatabaseSchema,
  EnrolledClient,
  ONLINE_THRESHOLD_MS,
  PhishingRule,
  StoredClient,
  ThreatAlert,
  UrlEvent,
  WhitelistRule
} from "./types";
import { IDatabase, UrlEventFilters, UrlEventsResult, DashboardStatsResult, ReportDataResult } from "./dbTypes";
import { PostgresDatabase } from "./pgdb";

const IS_SERVERLESS = Boolean(process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME);
const DATA_DIR = IS_SERVERLESS ? path.join("/tmp", "phishguard_data") : path.resolve(process.cwd(), "data");
const DB_FILE = path.join(DATA_DIR, "phishguard_db.json");
const BUNDLED_DB_FILE = path.resolve(process.cwd(), "data", "phishguard_db.json");
// URL events are append-only, one JSON object per line. This is the fix for
// "server takes too long to load history" as history grows: the old design
// stored urlEvents inside the same object as everything else and rewrote
// THE ENTIRE FILE (every client, rule, and every prior event) on every
// single new URL scan — an O(total history) write, every time, which is
// exactly why things slowed down and looked unreliable as history grew.
// Appending a single line is O(1) regardless of how large the history is.
const EVENTS_FILE = path.join(DATA_DIR, "url_events.jsonl");
const BUNDLED_EVENTS_FILE = path.resolve(process.cwd(), "data", "url_events.jsonl");

type MainSchema = Omit<DatabaseSchema, "urlEvents">;

const EMPTY_MAIN = (): MainSchema => ({
  clients: [],
  heartbeats: [],
  threatAlerts: [],
  whitelistRules: [],
  phishingRules: []
});

/**
 * File-backed database.
 *
 * ROOT-CAUSE FIX HISTORY (kept here because it explains why the storage is
 * shaped the way it is):
 *
 *  - "History sometimes complete, sometimes not / rule disappears after
 *    refresh": the previous version loaded the JSON file once at process
 *    start and only wrote back on a 100ms debounce, so a restart before
 *    that timer fired silently lost the write, and any other process
 *    touching the same file could stomp a stale in-memory copy over it.
 *    Fixed by always re-syncing with the file's on-disk state (cheap —
 *    only re-reads when mtime actually changed) before every read AND every
 *    write, and by flushing every mutation to disk synchronously and
 *    immediately — no debounce window at all.
 *
 *  - "Server takes too long to load history" / history flickers between
 *    partial and complete: rewriting the ENTIRE database file (every
 *    client, rule, and every prior URL event) on every single new scan is
 *    an O(n) disk write per event, so total cost across a growing history
 *    is O(n^2) — it gets slower and slower, and a slow synchronous write
 *    blocks the single-threaded event loop, which is exactly what could
 *    make a concurrent dashboard GET stall and appear to "come back empty
 *    then fill in." Fixed by moving urlEvents into their own append-only
 *    log file (url_events.jsonl): a new event is an O(1) fs.appendFileSync
 *    — it never rewrites anything that was already on disk. The small
 *    "main" file (clients/rules/alerts) still uses the safe full-rewrite
 *    approach, which is fine because it stays small and changes rarely.
 *
 * Caveat no in-process code can remove: on a deployment target where the
 * filesystem itself is not shared/persistent across instances (isolated
 * serverless containers with independent /tmp), no amount of file-based
 * logic can give cross-instance consistency — that needs an actual shared
 * datastore. Run this as a single persistent process for guaranteed
 * correctness (see isPossiblyEphemeralDeployment()).
 */
class FileDatabase implements IDatabase {
  private data: MainSchema = EMPTY_MAIN();
  private lastLoadedMtimeMs = 0;
  private initialized = false;

  // In-memory URL event log, kept in append (chronological, oldest-first)
  // order to match how it's appended on disk. Callers that want
  // newest-first (the whole rest of this app) get that ordering applied at
  // read time in getUrlEvents/getDashboardStats/getReportData.
  private urlEvents: UrlEvent[] = [];
  private eventsFileReadOffset = 0;
  private eventsInitialized = false;

  // Idempotency index over client-supplied eventIds. Rebuilt from the log
  // itself (never persisted separately, so it can never drift out of sync
  // with what is actually on disk). This is what makes the extension's
  // offline queue safe to replay: re-sending an event that already landed
  // is a no-op instead of a duplicate history row.
  private seenEventIds = new Set<string>();

  constructor() {
    this.ensureLoaded(true);
    this.ensureEventsLoaded(true);
  }

  // ─── Main (small) file: clients / rules / alerts / heartbeats ──────────
  private ensureLoaded(force = false) {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }

      const targetFile = fs.existsSync(DB_FILE)
        ? DB_FILE
        : fs.existsSync(BUNDLED_DB_FILE)
        ? BUNDLED_DB_FILE
        : null;

      if (!targetFile) {
        if (!this.initialized) {
          this.initialized = true;
          this.flushSync();
        }
        return;
      }

      const stat = fs.statSync(targetFile);
      if (!force && this.initialized && stat.mtimeMs <= this.lastLoadedMtimeMs) {
        return;
      }

      const raw = fs.readFileSync(targetFile, "utf-8");
      const parsed = JSON.parse(raw);
      this.data = {
        clients: Array.isArray(parsed.clients) ? parsed.clients : [],
        heartbeats: Array.isArray(parsed.heartbeats) ? parsed.heartbeats : [],
        threatAlerts: Array.isArray(parsed.threatAlerts) ? parsed.threatAlerts : [],
        whitelistRules: Array.isArray(parsed.whitelistRules) ? parsed.whitelistRules : [],
        phishingRules: Array.isArray(parsed.phishingRules) ? parsed.phishingRules : []
      };
      this.lastLoadedMtimeMs = stat.mtimeMs;
      this.initialized = true;

      // One-time migration: older versions of this app stored urlEvents
      // embedded inside this same file. If any are still there, migrate
      // them into the new append-only log so no history is lost.
      if (Array.isArray(parsed.urlEvents) && parsed.urlEvents.length > 0 && !this.eventsInitialized) {
        this.migrateLegacyEvents(parsed.urlEvents);
      }
    } catch (e) {
      console.warn("Database load warning (keeping last known-good in-memory state):", e);
      this.initialized = true;
    }
  }

  public flushSync() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      const tmpFile = `${DB_FILE}.tmp.${process.pid}.${Date.now()}`;
      fs.writeFileSync(tmpFile, JSON.stringify(this.data, null, 2), "utf-8");
      fs.renameSync(tmpFile, DB_FILE);
      const stat = fs.statSync(DB_FILE);
      this.lastLoadedMtimeMs = stat.mtimeMs;
    } catch (err) {
      console.error("Failed to persist database to disk:", err);
    }
  }

  // ─── Append-only URL event log ──────────────────────────────────────────
  private migrateLegacyEvents(legacyEvents: UrlEvent[]) {
    try {
      // Legacy array was newest-first; the log is oldest-first, so reverse.
      const chronological = [...legacyEvents].reverse();
      const lines = chronological.map(e => JSON.stringify(e)).join("\n") + "\n";
      fs.appendFileSync(EVENTS_FILE, lines, "utf-8");
      this.urlEvents.push(...chronological);
      const stat = fs.statSync(EVENTS_FILE);
      this.eventsFileReadOffset = stat.size;
      this.eventsInitialized = true;
      console.log(`Migrated ${chronological.length} legacy URL events into the append-only log.`);
    } catch (err) {
      console.error("Failed to migrate legacy URL events:", err);
    }
  }

  private ensureEventsLoaded(force = false) {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }

      const targetFile = fs.existsSync(EVENTS_FILE)
        ? EVENTS_FILE
        : fs.existsSync(BUNDLED_EVENTS_FILE)
        ? BUNDLED_EVENTS_FILE
        : null;

      if (!targetFile) {
        this.eventsInitialized = true;
        return;
      }

      const stat = fs.statSync(targetFile);

      if (force && !this.eventsInitialized) {
        // Full initial load.
        const raw = fs.readFileSync(targetFile, "utf-8");
        this.urlEvents = this.parseJsonlLines(raw);
        this.rebuildEventIdIndex();
        this.eventsFileReadOffset = stat.size;
        this.eventsInitialized = true;
        return;
      }

      if (stat.size > this.eventsFileReadOffset) {
        // Incremental read: only the bytes appended since we last looked —
        // O(new records), never O(total history), regardless of how large
        // the log has grown.
        const fd = fs.openSync(targetFile, "r");
        try {
          const length = stat.size - this.eventsFileReadOffset;
          const buffer = Buffer.alloc(length);
          fs.readSync(fd, buffer, 0, length, this.eventsFileReadOffset);
          const newLines = this.parseJsonlLines(buffer.toString("utf-8"));
          this.urlEvents.push(...newLines);
          for (const e of newLines) {
            if (e.eventId) this.seenEventIds.add(e.eventId);
          }
          this.eventsFileReadOffset = stat.size;
        } finally {
          fs.closeSync(fd);
        }
      } else if (stat.size < this.eventsFileReadOffset) {
        // File shrank/was replaced externally (e.g. manual reset) — reload
        // fully rather than risk reading with a stale offset.
        const raw = fs.readFileSync(targetFile, "utf-8");
        this.urlEvents = this.parseJsonlLines(raw);
        this.rebuildEventIdIndex();
        this.eventsFileReadOffset = stat.size;
      }
      this.eventsInitialized = true;
    } catch (e) {
      console.warn("URL event log load warning (keeping last known-good in-memory state):", e);
      this.eventsInitialized = true;
    }
  }

  private parseJsonlLines(raw: string): UrlEvent[] {
    const out: UrlEvent[] = [];
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        out.push(JSON.parse(trimmed));
      } catch {
        // Skip a malformed/partial line rather than fail the whole load.
      }
    }
    return out;
  }

  private rebuildEventIdIndex() {
    this.seenEventIds = new Set<string>();
    for (const e of this.urlEvents) {
      if (e.eventId) this.seenEventIds.add(e.eventId);
    }
  }

  /** True when this client-supplied eventId has already been stored. */
  public async hasEventId(eventId: string): Promise<boolean> {
    this.ensureEventsLoaded();
    return this.seenEventIds.has(eventId);
  }

  /**
   * Append one URL event.
   *
   * `eventId` (optional) is the client's idempotency key: if an event with
   * that key is already stored, nothing is written and the existing record
   * is returned. `occurredAt` (optional) is when the extension actually
   * observed the navigation — used so that an event which sat in the
   * offline queue for ten minutes is timestamped when it HAPPENED, not when
   * it finally reached the server. Both are omitted by the live /scan path,
   * which falls back to server time exactly as before.
   */
  public async recordUrlEvent(
    event: Omit<UrlEvent, "id" | "timestamp">,
    occurredAt?: string
  ): Promise<{ event: UrlEvent; wasNew: boolean }> {
    this.ensureLoaded();
    this.ensureEventsLoaded();

    // This check and the write below run with no `await` between them, so
    // there is no yield point for another request's handler to interleave
    // — the two together are as atomic as a single synchronous operation,
    // exactly like Postgres's own ON CONFLICT DO NOTHING.
    if (event.eventId && this.seenEventIds.has(event.eventId)) {
      const existing = this.urlEvents.find(e => e.eventId === event.eventId);
      if (existing) return { event: existing, wasNew: false };
    }

    // Normalize the timestamp: accept a client-observed time when it is a
    // valid date, otherwise fall back to server time. Always stored as an
    // ISO-8601 UTC string so every consumer parses it identically.
    let timestamp = new Date().toISOString();
    if (occurredAt) {
      const parsed = new Date(occurredAt);
      if (!Number.isNaN(parsed.getTime())) {
        // Guard against a client clock skewed into the future.
        timestamp = parsed.getTime() > Date.now() ? timestamp : parsed.toISOString();
      }
    }

    const newEvent: UrlEvent = {
      ...event,
      id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp
    };

    // Append to disk FIRST (durable, O(1)) — every monitored URL is
    // permanently stored and never evicted, restart-safe, and cheap
    // regardless of total history size.
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      const line = JSON.stringify(newEvent) + "\n";
      fs.appendFileSync(EVENTS_FILE, line, "utf-8");
      const stat = fs.statSync(EVENTS_FILE);
      this.eventsFileReadOffset = stat.size;
    } catch (err) {
      console.error("Failed to append URL event to disk:", err);
    }

    this.urlEvents.push(newEvent);
    if (newEvent.eventId) this.seenEventIds.add(newEvent.eventId);

    // Update client telemetry aggregates (small file, cheap full-rewrite)
    const client = this.data.clients.find(c => c.id === event.clientId);
    if (client) {
      client.telemetryStats.totalScanned++;
      if (event.classification === "PHISHING") client.telemetryStats.phishingBlocked++;
      else if (event.classification === "SUSPICIOUS") client.telemetryStats.suspiciousDetected++;
      else client.telemetryStats.safeEvaluated++;
      this.flushSync();
    }

    return { event: newEvent, wasNew: true };
  }

  /** Newest-first, matching every consumer's expectation. */
  private allEventsNewestFirst(): UrlEvent[] {
    this.ensureEventsLoaded();
    // this.urlEvents is oldest-first (append order); reverse for display.
    const out = new Array(this.urlEvents.length);
    for (let i = 0; i < this.urlEvents.length; i++) {
      out[i] = this.urlEvents[this.urlEvents.length - 1 - i];
    }
    return out;
  }

  public async getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult> {
    let filtered = this.allEventsNewestFirst();

    if (filters?.clientId && filters.clientId !== "ALL") {
      filtered = filtered.filter(e => e.clientId === filters.clientId);
    }

    if (filters?.classification && filters.classification !== "ALL") {
      filtered = filtered.filter(e => e.classification === filters.classification);
    }

    if (filters?.search && filters.search.trim()) {
      const q = filters.search.trim().toLowerCase();
      filtered = filtered.filter(e =>
        e.url.toLowerCase().includes(q) ||
        e.domain.toLowerCase().includes(q) ||
        e.clientName.toLowerCase().includes(q) ||
        e.reason.toLowerCase().includes(q)
      );
    }

    const total = filtered.length;
    const offset = filters?.offset || 0;
    // No artificial cap unless the caller asks for one — "complete history
    // in one load" means the default is "everything that matches," not a
    // silently-truncated page. Callers can still page via limit/offset.
    const limit = filters?.limit ?? total;
    const events = filtered.slice(offset, offset + limit);

    return { events, total };
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
    this.ensureLoaded();
    const now = new Date().toISOString();
    let client = this.data.clients.find(c => c.id === payload.clientId);

    if (client) {
      client.lastSeen = now;
      if (payload.clientName) client.clientName = payload.clientName;
      if (payload.os) client.os = payload.os;
      if (payload.browser) client.browser = payload.browser;
      if (payload.platform) client.platform = payload.platform;
      if (payload.extensionVersion) client.extensionVersion = payload.extensionVersion;
      if (payload.ip) client.ip = payload.ip;
      client.status = "ENROLLED";
    } else {
      client = {
        id: payload.clientId,
        clientName: payload.clientName || `Workstation-${payload.clientId.slice(-4).toUpperCase()}`,
        firstSeen: now,
        lastSeen: now,
        status: "ENROLLED",
        extensionVersion: payload.extensionVersion || "1.4",
        browser: payload.browser || "Chrome",
        os: payload.os || "Linux",
        platform: payload.platform || "x86_64",
        ip: payload.ip || "127.0.0.1",
        telemetryStats: {
          totalScanned: 0,
          phishingBlocked: 0,
          suspiciousDetected: 0,
          safeEvaluated: 0
        }
      };
      this.data.clients.unshift(client);
    }

    this.flushSync();
    return { ...client, connectionStatus: this.connectionStatusFor(client.lastSeen) };
  }

  public async heartbeatClient(clientId: string, stats?: Record<string, number>, clientName?: string, ip?: string): Promise<boolean> {
    this.ensureLoaded();
    const now = new Date().toISOString();
    const client = this.data.clients.find(c => c.id === clientId);

    if (!client) {
      await this.registerOrUpdateClient({ clientId, clientName, ip });
      return true;
    }

    client.lastSeen = now;
    client.status = "ENROLLED";
    if (clientName && !client.clientName) client.clientName = clientName;
    if (ip) client.ip = ip;

    if (stats) {
      if (typeof stats.total === "number") client.telemetryStats.totalScanned = Math.max(client.telemetryStats.totalScanned, stats.total);
      if (typeof stats.phishing === "number") client.telemetryStats.phishingBlocked = Math.max(client.telemetryStats.phishingBlocked, stats.phishing);
      if (typeof stats.suspicious === "number") client.telemetryStats.suspiciousDetected = Math.max(client.telemetryStats.suspiciousDetected, stats.suspicious);
      if (typeof stats.safe === "number") client.telemetryStats.safeEvaluated = Math.max(client.telemetryStats.safeEvaluated, stats.safe);
    }

    this.data.heartbeats.unshift({
      id: `hb_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      clientId,
      timestamp: now,
      stats
    });
    if (this.data.heartbeats.length > 500) {
      this.data.heartbeats.pop();
    }

    this.flushSync();
    return true;
  }

  /**
   * Per-system counts derived from the persistent event log.
   *
   * The stored `telemetryStats` are also fed by the extension heartbeat,
   * whose source counters live in the service worker's memory and reset
   * whenever Chrome suspends it. That made "Enrolled Systems" disagree with
   * Overview and URL History for the same system. Every read-facing count
   * is now derived from the same authoritative records everything else
   * counts, so the three views cannot drift apart.
   */
  /**
   * Derives every system's counts in ONE pass over the log, not one pass
   * per system — the dashboard polls this endpoint every few seconds, so a
   * per-client scan would reintroduce exactly the kind of O(systems x
   * history) cost that made this app slow down as history grew.
   */
  private derivedTelemetryByClient(): Map<string, EnrolledClient["telemetryStats"]> {
    this.ensureEventsLoaded();
    const map = new Map<string, EnrolledClient["telemetryStats"]>();
    for (const e of this.urlEvents) {
      let t = map.get(e.clientId);
      if (!t) {
        t = { totalScanned: 0, phishingBlocked: 0, suspiciousDetected: 0, safeEvaluated: 0 };
        map.set(e.clientId, t);
      }
      t.totalScanned++;
      const b = this.bucketOf(e);
      if (b === "phishing") t.phishingBlocked++;
      else if (b === "suspicious") t.suspiciousDetected++;
      else t.safeEvaluated++;
    }
    return map;
  }

  private static readonly ZERO_TELEMETRY: EnrolledClient["telemetryStats"] = {
    totalScanned: 0, phishingBlocked: 0, suspiciousDetected: 0, safeEvaluated: 0
  };

  private connectionStatusFor(lastSeen: string): "ONLINE" | "OFFLINE" {
    return Date.now() - new Date(lastSeen).getTime() < ONLINE_THRESHOLD_MS ? "ONLINE" : "OFFLINE";
  }

  public async getClients(): Promise<EnrolledClient[]> {
    this.ensureLoaded();
    const derived = this.derivedTelemetryByClient();
    return this.data.clients.map(c => ({
      ...c,
      telemetryStats: derived.get(c.id) || { ...FileDatabase.ZERO_TELEMETRY },
      connectionStatus: this.connectionStatusFor(c.lastSeen)
    }));
  }

  /**
   * Cheap existence check for hot request paths (/scan, /bulk-scan) that
   * only need to know whether a client is enrolled. Deliberately does NOT
   * touch the event log.
   */
  public async clientExists(id: string): Promise<boolean> {
    this.ensureLoaded();
    return this.data.clients.some(c => c.id === id);
  }

  public async getClientById(id: string): Promise<EnrolledClient | null> {
    this.ensureLoaded();
    const client = this.data.clients.find(c => c.id === id);
    if (!client) return null;
    const derived = this.derivedTelemetryByClient();
    return {
      ...client,
      telemetryStats: derived.get(client.id) || { ...FileDatabase.ZERO_TELEMETRY },
      connectionStatus: this.connectionStatusFor(client.lastSeen)
    };
  }

  public async deleteClient(id: string): Promise<boolean> {
    this.ensureLoaded();
    const idx = this.data.clients.findIndex(c => c.id === id);
    if (idx === -1) return false;
    this.data.clients.splice(idx, 1);
    this.flushSync();
    return true;
  }

  // ─── Threat Alerts ───────────────────────────────────────────────────────
  public async recordThreatAlert(alert: Omit<ThreatAlert, "id" | "timestamp" | "status">): Promise<ThreatAlert> {
    this.ensureLoaded();
    const newAlert: ThreatAlert = {
      ...alert,
      id: `alt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      status: "ACTIVE"
    };

    this.data.threatAlerts.unshift(newAlert);
    this.flushSync();
    return newAlert;
  }

  public async getThreatAlerts(clientId?: string): Promise<ThreatAlert[]> {
    this.ensureLoaded();
    if (clientId && clientId !== "ALL") {
      return this.data.threatAlerts.filter(a => a.clientId === clientId);
    }
    return [...this.data.threatAlerts];
  }

  public async updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED"): Promise<boolean> {
    this.ensureLoaded();
    const alert = this.data.threatAlerts.find(a => a.id === id);
    if (!alert) return false;
    alert.status = status;
    this.flushSync();
    return true;
  }

  // ─── Rules ───────────────────────────────────────────────────────────────
  public async getWhitelistRules(): Promise<WhitelistRule[]> {
    this.ensureLoaded();
    return [...this.data.whitelistRules];
  }

  public async addWhitelistRule(pattern: string, description: string, addedBy = "Admin"): Promise<WhitelistRule> {
    this.ensureLoaded();
    const cleanPattern = pattern.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    const existing = this.data.whitelistRules.find(r => r.pattern === cleanPattern);
    if (existing) return existing;

    const rule: WhitelistRule = {
      id: `wl_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      pattern: cleanPattern,
      description: description.trim() || "Whitelisted domain",
      createdAt: new Date().toISOString(),
      addedBy
    };
    this.data.whitelistRules.push(rule);
    this.flushSync();
    return rule;
  }

  public async deleteWhitelistRule(id: string): Promise<boolean> {
    this.ensureLoaded();
    const idx = this.data.whitelistRules.findIndex(r => r.id === id);
    if (idx === -1) return false;
    this.data.whitelistRules.splice(idx, 1);
    this.flushSync();
    return true;
  }

  public async getPhishingRules(): Promise<PhishingRule[]> {
    this.ensureLoaded();
    return [...this.data.phishingRules];
  }

  public async addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string, addedBy = "Admin"): Promise<PhishingRule> {
    this.ensureLoaded();
    const cleanPattern = pattern.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    const existing = this.data.phishingRules.find(r => r.pattern === cleanPattern);
    if (existing) return existing;

    const rule: PhishingRule = {
      id: `ph_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      pattern: cleanPattern,
      severity,
      reason: reason.trim() || "Identified malicious phishing target",
      createdAt: new Date().toISOString(),
      addedBy
    };
    this.data.phishingRules.push(rule);
    this.flushSync();
    return rule;
  }

  public async deletePhishingRule(id: string): Promise<boolean> {
    this.ensureLoaded();
    const idx = this.data.phishingRules.findIndex(r => r.id === id);
    if (idx === -1) return false;
    this.data.phishingRules.splice(idx, 1);
    this.flushSync();
    return true;
  }

  /**
   * THE single classification-bucketing rule for the whole application.
   *
   * Every consumer (Overview, Reports, per-system rollups) counts through
   * this one function, so they can never disagree about which bucket a
   * record falls into. Anything that is not explicitly SUSPICIOUS or
   * PHISHING is counted as SAFE — deliberately, so that
   *
   *     total === safe + suspicious + phishing
   *
   * holds by construction for ANY record set, including legacy rows or a
   * record with a missing/unrecognised classification. Previously such a
   * record was counted in the total but in none of the three buckets, so
   * the three numbers silently failed to add up to the total.
   */
  private bucketOf(e: UrlEvent): "safe" | "suspicious" | "phishing" {
    if (e.classification === "PHISHING") return "phishing";
    if (e.classification === "SUSPICIOUS") return "suspicious";
    return "safe";
  }

  private countBuckets(events: UrlEvent[]) {
    let safe = 0, suspicious = 0, phishing = 0;
    for (const e of events) {
      const b = this.bucketOf(e);
      if (b === "phishing") phishing++;
      else if (b === "suspicious") suspicious++;
      else safe++;
    }
    return { safe, suspicious, phishing };
  }

  // ─── Dashboard Statistics ────────────────────────────────────────────────
  /**
   * Overview statistics, computed from the persistent event log only.
   *
   * `clientId` scopes every number to one enrolled system. Previously this
   * method took no scope at all, so the Overview always showed fleet-wide
   * totals while URL History showed the selected system — the two views
   * disagreed by design, which reads as "the counts are wrong."
   */
  public async getDashboardStats(clientId?: string): Promise<DashboardStatsResult> {
    this.ensureLoaded();
    const isGlobal = !clientId || clientId === "ALL";
    const totalSystems = this.data.clients.length;

    const allEvents = this.allEventsNewestFirst();
    const events = isGlobal ? allEvents : allEvents.filter(e => e.clientId === clientId);

    const urlsMonitored = events.length;
    const { safe: safeCount, suspicious: suspiciousCount, phishing: phishingCount } =
      this.countBuckets(events);

    const allowedUrls = safeCount;
    const phishingIntercepted = phishingCount;

    const scopedAlerts = isGlobal
      ? this.data.threatAlerts
      : this.data.threatAlerts.filter(a => a.clientId === clientId);
    const activeAlerts = scopedAlerts.filter(a => a.status === "ACTIVE").length;

    const threatDomainCounts = new Map<string, number>();
    scopedAlerts.forEach(a => {
      if (a.domain) {
        threatDomainCounts.set(a.domain, (threatDomainCounts.get(a.domain) || 0) + 1);
      }
    });

    const topThreatDomains = Array.from(threatDomainCounts.entries())
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const recentEvents = events.slice(0, 10);

    return {
      scope: isGlobal ? "ALL" : clientId,
      totalSystems,
      urlsMonitored,
      allowedUrls,
      phishingIntercepted,
      activeAlerts,
      breakdown: {
        evaluated: urlsMonitored,
        safe: safeCount,
        suspicious: suspiciousCount,
        phishing: phishingCount
      },
      recentEvents,
      topThreatDomains
    };
  }

  // ─── Report Data (strictly scoped — never leaks another system's data) ───
  public async getReportData(clientId?: string): Promise<ReportDataResult> {
    this.ensureLoaded();
    const isGlobal = !clientId || clientId === "ALL";
    const allEvents = this.allEventsNewestFirst();

    const events = isGlobal
      ? allEvents
      : allEvents.filter(e => e.clientId === clientId);

    const alerts = isGlobal
      ? this.data.threatAlerts
      : this.data.threatAlerts.filter(a => a.clientId === clientId);

    const clients: EnrolledClient[] = (isGlobal
      ? this.data.clients
      : this.data.clients.filter(c => c.id === clientId)
    ).map(c => ({ ...c, connectionStatus: this.connectionStatusFor(c.lastSeen) }));

    const { safe: safeCount, suspicious: suspiciousCount, phishing: phishingCount } =
      this.countBuckets(events);

    const threatDomainCounts = new Map<string, number>();
    alerts.forEach(a => {
      if (a.domain) threatDomainCounts.set(a.domain, (threatDomainCounts.get(a.domain) || 0) + 1);
    });
    const topThreatDomains = Array.from(threatDomainCounts.entries())
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const perSystem = isGlobal
      ? this.data.clients.map(c => {
          const clientEvents = allEvents.filter(e => e.clientId === c.id);
          const clientAlerts = this.data.threatAlerts.filter(a => a.clientId === c.id);
          const b = this.countBuckets(clientEvents);
          return {
            clientId: c.id,
            clientName: c.clientName,
            os: c.os,
            browser: c.browser,
            totalScanned: clientEvents.length,
            safe: b.safe,
            suspicious: b.suspicious,
            phishing: b.phishing,
            activeAlerts: clientAlerts.filter(a => a.status === "ACTIVE").length
          };
        })
      : [];

    return {
      scope: isGlobal ? "ALL" : clientId,
      generatedAt: new Date().toISOString(),
      systems: clients,
      summary: {
        totalEvaluated: events.length,
        safe: safeCount,
        suspicious: suspiciousCount,
        phishing: phishingCount,
        activeAlerts: alerts.filter(a => a.status === "ACTIVE").length
      },
      topThreatDomains,
      events: events.slice(0, 1000),
      alerts: alerts.slice(0, 500),
      perSystem
    };
  }

  public isPossiblyEphemeralDeployment(): boolean {
    return IS_SERVERLESS;
  }
}

export const FileDatabaseImpl = FileDatabase;

/**
 * Storage backend selection.
 *
 * DATABASE_URL set  -> PostgresDatabase: a real external database, the
 *   only backend that stays consistent across multiple independent
 *   server/function instances (see server/pgdb.ts's file header for why
 *   that matters).
 * DATABASE_URL unset -> FileDatabase: zero-config local files, correct
 *   for a single always-on process (e.g. `npm run dev` / `npm start` on a
 *   normal host), but NOT safe across independent serverless instances.
 *
 * FileDatabase is constructed lazily, ONLY in the branch that actually
 * selects it — its constructor touches the local filesystem (creates the
 * data directory, reads/writes files), which is unnecessary work, and in
 * some deploy targets could even hit a read-only path, when Postgres is
 * what's actually going to serve every request.
 *
 * This is a one-time choice made when the module first loads, and every
 * route in server/app.ts and server/detector.ts programs against the
 * shared IDatabase interface, so nothing else in the codebase needs to
 * know or care which backend is active.
 */
function selectDatabase(): IDatabase {
  const url = process.env.DATABASE_URL;
  if (url && url.trim()) {
    console.log("PhishGuard: using Postgres-backed storage (DATABASE_URL is set) — consistent across all instances.");
    return new PostgresDatabase(url);
  }
  console.log("PhishGuard: using local file-backed storage (no DATABASE_URL set) — correct for a single long-lived process only.");
  return new FileDatabase();
}

export const db: IDatabase = selectDatabase();
