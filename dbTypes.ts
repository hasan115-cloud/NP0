import {
  EnrolledClient,
  PhishingRule,
  ThreatAlert,
  UrlEvent,
  WhitelistRule
} from "./types";

export interface UrlEventFilters {
  clientId?: string;
  classification?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface UrlEventsResult {
  events: UrlEvent[];
  total: number;
}

export interface DashboardStatsResult {
  scope: string;
  totalSystems: number;
  urlsMonitored: number;
  allowedUrls: number;
  phishingIntercepted: number;
  activeAlerts: number;
  breakdown: {
    evaluated: number;
    safe: number;
    suspicious: number;
    phishing: number;
  };
  recentEvents: UrlEvent[];
  topThreatDomains: { domain: string; count: number }[];
}

export interface ReportDataResult {
  scope: string;
  generatedAt: string;
  systems: EnrolledClient[];
  summary: {
    totalEvaluated: number;
    safe: number;
    suspicious: number;
    phishing: number;
    activeAlerts: number;
  };
  topThreatDomains: { domain: string; count: number }[];
  events: UrlEvent[];
  alerts: ThreatAlert[];
  perSystem: {
    clientId: string;
    clientName: string;
    os: string;
    browser: string;
    totalScanned: number;
    safe: number;
    suspicious: number;
    phishing: number;
    activeAlerts: number;
  }[];
}

/**
 * The one storage contract every route in server/app.ts and server/detector.ts
 * programs against. Two implementations exist:
 *
 *  - FileDatabase (server/db.ts) — zero-config JSON/JSONL files on local
 *    disk. Correct and fast for a single, long-lived Node process (the
 *    default: `npm run dev` / `npm start`, or an always-on host). NOT safe
 *    across multiple independent serverless function instances, because
 *    each one gets its own filesystem — see the warning surfaced via
 *    isPossiblyEphemeralDeployment().
 *
 *  - PostgresDatabase (server/pgdb.ts) — a real external database, used
 *    automatically whenever DATABASE_URL is set. This is what makes
 *    storage consistent across MANY independent server/function instances
 *    (Netlify Functions, multiple Cloud Run replicas, etc.): they all read
 *    and write the same external database, so a poll request routed to a
 *    different instance than the one that received the last URL event
 *    still sees it.
 *
 * Every method is async so both implementations can share this interface;
 * FileDatabase's methods are synchronous internally and simply return an
 * already-resolved Promise, so its logic and behavior are unchanged.
 */
export interface IDatabase {
  // Rules
  getWhitelistRules(): Promise<WhitelistRule[]>;
  addWhitelistRule(pattern: string, description: string, addedBy?: string): Promise<WhitelistRule>;
  deleteWhitelistRule(id: string): Promise<boolean>;
  getPhishingRules(): Promise<PhishingRule[]>;
  addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string, addedBy?: string): Promise<PhishingRule>;
  deletePhishingRule(id: string): Promise<boolean>;

  // Clients
  registerOrUpdateClient(payload: {
    clientId: string;
    clientName?: string;
    os?: string;
    browser?: string;
    platform?: string;
    extensionVersion?: string;
    ip?: string;
  }): Promise<EnrolledClient>;
  heartbeatClient(clientId: string, stats?: Record<string, number>, clientName?: string, ip?: string): Promise<boolean>;
  getClients(): Promise<EnrolledClient[]>;
  clientExists(id: string): Promise<boolean>;
  getClientById(id: string): Promise<EnrolledClient | null>;
  deleteClient(id: string): Promise<boolean>;

  // Threat alerts
  recordThreatAlert(alert: Omit<ThreatAlert, "id" | "timestamp" | "status">): Promise<ThreatAlert>;
  getThreatAlerts(clientId?: string): Promise<ThreatAlert[]>;
  updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED"): Promise<boolean>;

  // URL events (the authoritative history)
  //
  // hasEventId() is a read-only diagnostic — it must NEVER be used as a
  // "check, then write" pre-check before recordUrlEvent(). Two concurrent
  // requests (from two different instances, or even two requests on one
  // instance interleaved across an await) can both see "not present yet"
  // and both proceed, and while the database still correctly stores only
  // one row (recordUrlEvent's own conflict handling is atomic), a
  // check-then-write caller has no way to know that only one of the two
  // calls actually inserted. recordUrlEvent's `wasNew` return value is the
  // ONLY correct way to distinguish a genuine new write from a dedup hit —
  // it comes from the same atomic operation that performed the write.
  hasEventId(eventId: string): Promise<boolean>;
  recordUrlEvent(event: Omit<UrlEvent, "id" | "timestamp">, occurredAt?: string): Promise<{ event: UrlEvent; wasNew: boolean }>;
  getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult>;

  // Aggregates
  getDashboardStats(clientId?: string): Promise<DashboardStatsResult>;
  getReportData(clientId?: string): Promise<ReportDataResult>;

  // Deployment diagnostics — pure/synchronous, no I/O in either backend.
  isPossiblyEphemeralDeployment(): boolean;
}
