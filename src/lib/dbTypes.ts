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

export interface IDatabase {
  getWhitelistRules(): Promise<WhitelistRule[]>;
  addWhitelistRule(pattern: string, description: string, addedBy?: string): Promise<WhitelistRule>;
  deleteWhitelistRule(id: string): Promise<boolean>;
  getPhishingRules(): Promise<PhishingRule[]>;
  addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string, addedBy?: string): Promise<PhishingRule>;
  deletePhishingRule(id: string): Promise<boolean>;

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

  recordThreatAlert(alert: Omit<ThreatAlert, "id" | "timestamp" | "status">): Promise<ThreatAlert>;
  getThreatAlerts(clientId?: string): Promise<ThreatAlert[]>;
  updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED"): Promise<boolean>;

  hasEventId(eventId: string): Promise<boolean>;
  recordUrlEvent(event: Omit<UrlEvent, "id" | "timestamp">, occurredAt?: string): Promise<{ event: UrlEvent; wasNew: boolean }>;
  getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult>;

  getDashboardStats(clientId?: string): Promise<DashboardStatsResult>;
  getReportData(clientId?: string): Promise<ReportDataResult>;

  isPossiblyEphemeralDeployment(): boolean;
  getDatabaseInfo?(): { isSupabase: boolean; host: string };
}
