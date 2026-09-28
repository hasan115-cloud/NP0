import { IDatabase, UrlEventFilters, UrlEventsResult, DashboardStatsResult, ReportDataResult } from "./dbTypes";
import { EnrolledClient, PhishingRule, ThreatAlert, UrlEvent, WhitelistRule } from "./types";

export class ResilientDatabase implements IDatabase {
  private primary: IDatabase;
  private secondary?: IDatabase;
  private primaryFailedRecently = false;
  private lastFailureTime = 0;
  private failureCooldownMs = 30_000; // 30s cooldown before retrying primary if it failed hard

  constructor(primary: IDatabase, secondary?: IDatabase) {
    this.primary = primary;
    this.secondary = secondary;
  }

  private isPrimaryCoolingDown(): boolean {
    if (this.primaryFailedRecently && Date.now() - this.lastFailureTime < this.failureCooldownMs) {
      return true;
    }
    this.primaryFailedRecently = false;
    return false;
  }

  private markPrimaryFailure(err: any) {
    this.primaryFailedRecently = true;
    this.lastFailureTime = Date.now();
    console.warn("Primary database operation failed, falling back to secondary:", err?.message || err);
  }

  private async execute<T>(fn: (db: IDatabase) => Promise<T>, fallbackValue?: T): Promise<T> {
    if (!this.secondary) {
      return fn(this.primary);
    }

    if (this.isPrimaryCoolingDown()) {
      try {
        return await fn(this.secondary);
      } catch (secErr) {
        console.warn("Secondary database also had issue:", secErr);
        if (fallbackValue !== undefined) return fallbackValue;
        throw secErr;
      }
    }

    try {
      return await fn(this.primary);
    } catch (err: any) {
      this.markPrimaryFailure(err);
      try {
        return await fn(this.secondary);
      } catch (secErr) {
        console.warn("Secondary database also failed:", secErr);
        if (fallbackValue !== undefined) return fallbackValue;
        throw secErr;
      }
    }
  }

  public getDatabaseInfo(): { isSupabase: boolean; host: string } {
    if (this.primary.getDatabaseInfo) {
      return this.primary.getDatabaseInfo();
    }
    if (this.secondary && this.secondary.getDatabaseInfo) {
      return this.secondary.getDatabaseInfo();
    }
    return { isSupabase: false, host: "resilient" };
  }

  public isPossiblyEphemeralDeployment(): boolean {
    return this.primary.isPossiblyEphemeralDeployment();
  }

  public async getWhitelistRules(): Promise<WhitelistRule[]> {
    return this.execute(d => d.getWhitelistRules(), []);
  }

  public async addWhitelistRule(pattern: string, description: string, addedBy?: string): Promise<WhitelistRule> {
    return this.execute(d => d.addWhitelistRule(pattern, description, addedBy));
  }

  public async deleteWhitelistRule(id: string): Promise<boolean> {
    return this.execute(d => d.deleteWhitelistRule(id), true);
  }

  public async getPhishingRules(): Promise<PhishingRule[]> {
    return this.execute(d => d.getPhishingRules(), []);
  }

  public async addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string, addedBy?: string): Promise<PhishingRule> {
    return this.execute(d => d.addPhishingRule(pattern, severity, reason, addedBy));
  }

  public async deletePhishingRule(id: string): Promise<boolean> {
    return this.execute(d => d.deletePhishingRule(id), true);
  }

  public async registerOrUpdateClient(payload: {
    clientId: string;
    clientName?: string;
    os?: string;
    browser?: string;
    platform?: string;
    extensionVersion?: string;
    ip?: string;
  }): Promise<EnrolledClient> {
    return this.execute(d => d.registerOrUpdateClient(payload));
  }

  public async heartbeatClient(clientId: string, stats?: Record<string, number>, clientName?: string, ip?: string): Promise<boolean> {
    return this.execute(d => d.heartbeatClient(clientId, stats, clientName, ip), true);
  }

  public async getClients(): Promise<EnrolledClient[]> {
    return this.execute(d => d.getClients(), []);
  }

  public async clientExists(id: string): Promise<boolean> {
    return this.execute(d => d.clientExists(id), false);
  }

  public async getClientById(id: string): Promise<EnrolledClient | null> {
    return this.execute(d => d.getClientById(id), null);
  }

  public async deleteClient(id: string): Promise<boolean> {
    return this.execute(d => d.deleteClient(id), true);
  }

  public async recordThreatAlert(alert: Omit<ThreatAlert, "id" | "timestamp" | "status">): Promise<ThreatAlert> {
    return this.execute(d => d.recordThreatAlert(alert));
  }

  public async getThreatAlerts(clientId?: string): Promise<ThreatAlert[]> {
    return this.execute(d => d.getThreatAlerts(clientId), []);
  }

  public async updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED"): Promise<boolean> {
    return this.execute(d => d.updateThreatAlertStatus(id, status), true);
  }

  public async hasEventId(eventId: string): Promise<boolean> {
    return this.execute(d => d.hasEventId(eventId), false);
  }

  public async recordUrlEvent(
    event: Omit<UrlEvent, "id" | "timestamp">,
    occurredAt?: string
  ): Promise<{ event: UrlEvent; wasNew: boolean }> {
    return this.execute(d => d.recordUrlEvent(event, occurredAt));
  }

  public async getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult> {
    return this.execute(d => d.getUrlEvents(filters), { events: [], total: 0 });
  }

  public async getDashboardStats(clientId?: string): Promise<DashboardStatsResult> {
    return this.execute(d => d.getDashboardStats(clientId), {
      scope: clientId || "ALL",
      totalSystems: 0,
      urlsMonitored: 0,
      allowedUrls: 0,
      phishingIntercepted: 0,
      activeAlerts: 0,
      breakdown: { evaluated: 0, safe: 0, suspicious: 0, phishing: 0 },
      recentEvents: [],
      topThreatDomains: []
    });
  }

  public async getReportData(clientId?: string): Promise<ReportDataResult> {
    return this.execute(d => d.getReportData(clientId));
  }
}
