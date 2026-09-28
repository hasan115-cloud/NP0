export type SystemStatus = "ENROLLED";

// A system is heartbeating roughly every 30s (see the extension's
// pg_heartbeat alarm). Three missed heartbeats — 90s of silence — is
// treated as OFFLINE for display purposes. This is used ONLY to compute
// the read-time `connectionStatus` field below; it never removes a
// client, never affects Total Enrolled Systems, and is never persisted.
// A late or missing heartbeat means "this system currently looks
// unreachable," not "this system was uninstalled" — those are two
// different, independently-triggered events, and only an explicit
// DELETE /api/clients/:id call removes a client record.
export const ONLINE_THRESHOLD_MS = 90_000;
export type UrlClassification = "SAFE" | "SUSPICIOUS" | "PHISHING";
export type UrlVerdict = "ALLOWED" | "WARNING" | "BLOCKED";
export type ThreatStatus = "ACTIVE" | "ACKNOWLEDGED" | "RESOLVED";

// The shape actually persisted for a client — deliberately does NOT
// include connectionStatus, which is derived at read time from `lastSeen`
// and would otherwise go stale the instant it's written to disk/a row.
export interface StoredClient {
  id: string;
  clientName: string;
  firstSeen: string;
  lastSeen: string;
  status: SystemStatus;
  extensionVersion: string;
  browser: string;
  os: string;
  platform: string;
  ip: string;
  telemetryStats: {
    totalScanned: number;
    phishingBlocked: number;
    suspiciousDetected: number;
    safeEvaluated: number;
  };
}

// The API-facing shape: everything stored, plus the derived, point-in-time
// connectionStatus. Every read path (getClients, getClientById,
// registerOrUpdateClient, heartbeatClient's implicit re-registration)
// returns this, computed fresh from the current time — never persisted.
export interface EnrolledClient extends StoredClient {
  // "OFFLINE" means no heartbeat recently, NOT "uninstalled": this system
  // still counts toward Total Enrolled Systems and still appears in every
  // list until an explicit delete happens. See ONLINE_THRESHOLD_MS below.
  connectionStatus: "ONLINE" | "OFFLINE";
}

export interface HeartbeatLog {
  id: string;
  clientId: string;
  timestamp: string;
  stats?: Record<string, number>;
}

export interface UrlEvent {
  id: string;
  // Client-generated idempotency key. The extension mints this ONCE, at the
  // moment the URL is observed, and reuses it for every retry of that same
  // observation. The server stores it and refuses to record the same
  // eventId twice, so an offline-queue replay or a network retry can never
  // create a duplicate history row. Absent on legacy records written before
  // this field existed — those are left exactly as they are.
  eventId?: string;
  timestamp: string;
  clientId: string;
  clientName: string;
  url: string;
  domain: string;
  classification: UrlClassification;
  verdict: UrlVerdict;
  score: number;
  reason: string;
  source: string;
  // True when this verdict came from an administrator-configured Whitelist
  // or Phishing/Blacklist rule match (as opposed to the heuristic scorer).
  // Drives the "Rule Triggered" label in the dashboard's URL History —
  // this is set only from the actual rule-match result returned by
  // classifyUrl(), never inferred or faked client-side.
  ruleTriggered?: boolean;
  ruleType?: "WHITELIST" | "PHISHING" | null;
}

export interface ThreatAlert {
  id: string;
  timestamp: string;
  clientId: string;
  clientName: string;
  url: string;
  domain: string;
  score: number;
  reasons: string[];
  source: string;
  status: ThreatStatus;
}

export interface WhitelistRule {
  id: string;
  pattern: string;
  description: string;
  createdAt: string;
  addedBy: string;
}

export interface PhishingRule {
  id: string;
  pattern: string;
  severity: "HIGH" | "CRITICAL";
  reason: string;
  createdAt: string;
  addedBy: string;
}

export interface DatabaseSchema {
  clients: StoredClient[];
  heartbeats: HeartbeatLog[];
  urlEvents: UrlEvent[];
  threatAlerts: ThreatAlert[];
  whitelistRules: WhitelistRule[];
  phishingRules: PhishingRule[];
}

export type NavigationTab =
  | "overview"
  | "enrolled_systems"
  | "url_history"
  | "security_rules"
  | "threat_alerts"
  | "install_extension"
  | "reports";

export interface DashboardStats {
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

export interface ReportData {
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
    alerts?: number;
    activeAlerts: number;
  }[];
}

