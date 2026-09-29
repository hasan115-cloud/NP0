import { SupabaseClient } from "@supabase/supabase-js";
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

export class SupabaseRestDatabase implements IDatabase {
  private client: SupabaseClient;
  private projectUrl: string;
  private memoryCache: {
    clients: Map<string, any>;
    events: any[];
    alerts: any[];
    whitelist: any[];
    phishing: any[];
  };

  constructor(client: SupabaseClient, projectUrl: string = "") {
    this.client = client;
    this.projectUrl = projectUrl;
    this.memoryCache = {
      clients: new Map(),
      events: [],
      alerts: [],
      whitelist: [],
      phishing: []
    };
  }

  public getDatabaseInfo(): { isSupabase: boolean; host: string } {
    let host = "supabase-rest";
    try {
      if (this.projectUrl) {
        host = new URL(this.projectUrl).hostname;
      }
    } catch {}
    return { isSupabase: true, host };
  }

  public isPossiblyEphemeralDeployment(): boolean {
    return Boolean(
      process.env.VERCEL ||
      process.env.VERCEL_ENV ||
      process.env.NETLIFY ||
      process.env.AWS_LAMBDA_FUNCTION_NAME
    );
  }

  // ─── Mapping helpers ────────────────────────────────────────────────────────
  private mapClient(r: any): EnrolledClient {
    const timeVal = r.last_seen || r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const lastSeenIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    const firstSeenVal = r.first_seen || r.created_at || new Date();
    const parsedFirst = new Date(firstSeenVal);
    const firstSeenIso = !isNaN(parsedFirst.getTime()) ? parsedFirst.toISOString() : new Date().toISOString();

    return {
      id: r.id,
      clientName: r.client_name || r.clientName || "Workstation",
      firstSeen: firstSeenIso,
      lastSeen: lastSeenIso,
      status: r.status || "ENROLLED",
      connectionStatus: Date.now() - new Date(lastSeenIso).getTime() < ONLINE_THRESHOLD_MS ? "ONLINE" : "OFFLINE",
      extensionVersion: r.extension_version || r.extensionVersion || "1.4",
      browser: r.browser || "Chrome",
      os: r.os || "Linux",
      platform: r.platform || "x86_64",
      ip: r.ip || "remote-ip",
      telemetryStats: { totalScanned: 0, phishingBlocked: 0, suspiciousDetected: 0, safeEvaluated: 0 }
    };
  }

  private mapUrlEvent(r: any): UrlEvent {
    const timeVal = r.occurred_at || r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const validIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      eventId: r.event_id || r.eventId || undefined,
      timestamp: validIso,
      clientId: r.client_id || r.clientId || "unknown",
      clientName: r.client_name || r.clientName || "Workstation",
      url: r.url,
      domain: r.domain,
      classification: r.classification,
      verdict: r.verdict,
      score: typeof r.score === "number" ? r.score : parseFloat(r.score || "0"),
      reason: r.reason,
      source: r.source || "extension",
      ruleTriggered: Boolean(r.rule_triggered || r.ruleTriggered),
      ruleType: r.rule_type || r.ruleType || null
    };
  }

  private mapThreatAlert(r: any): ThreatAlert {
    const timeVal = r.occurred_at || r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const validIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      timestamp: validIso,
      clientId: r.client_id || r.clientId || "unknown",
      clientName: r.client_name || r.clientName || "Workstation",
      url: r.url,
      domain: r.domain,
      score: typeof r.score === "number" ? r.score : parseFloat(r.score || "0"),
      reasons: Array.isArray(r.reasons) ? r.reasons : [],
      source: r.source || "extension",
      status: r.status || "ACTIVE"
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
      addedBy: r.added_by || r.addedBy || "Admin"
    };
  }

  private mapPhishingRule(r: any): PhishingRule {
    const timeVal = r.created_at || new Date();
    const parsedTime = new Date(timeVal);
    const validIso = !isNaN(parsedTime.getTime()) ? parsedTime.toISOString() : new Date().toISOString();
    return {
      id: r.id,
      pattern: r.pattern,
      severity: r.severity || "HIGH",
      reason: r.reason || "Threat rule",
      createdAt: validIso,
      addedBy: r.added_by || r.addedBy || "Admin"
    };
  }

  // ─── Whitelist Rules ────────────────────────────────────────────────────────
  public async getWhitelistRules(): Promise<WhitelistRule[]> {
    try {
      const { data, error } = await this.client.from("whitelist_rules").select("*");
      if (error || !data || data.length === 0) {
        return this.getDefaultWhitelistRules();
      }
      return data.map(this.mapWhitelistRule);
    } catch {
      return this.getDefaultWhitelistRules();
    }
  }

  private getDefaultWhitelistRules(): WhitelistRule[] {
    return [
      { id: "wl_corp_internal", pattern: "*.corp.internal", description: "Corporate internal network and infrastructure", createdAt: new Date().toISOString(), addedBy: "System Policy" },
      { id: "wl_google_ws", pattern: "*.google.com", description: "Google Workspace and enterprise authentication", createdAt: new Date().toISOString(), addedBy: "System Policy" },
      { id: "wl_msft_365", pattern: "*.microsoft.com", description: "Microsoft 365, Azure AD, and Office services", createdAt: new Date().toISOString(), addedBy: "System Policy" },
      { id: "wl_github", pattern: "*.github.com", description: "Enterprise GitHub source repositories", createdAt: new Date().toISOString(), addedBy: "System Policy" }
    ];
  }

  public async addWhitelistRule(pattern: string, description: string, addedBy = "Admin"): Promise<WhitelistRule> {
    const id = `wl_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const row = { id, pattern, description, added_by: addedBy };
    try {
      const { data, error } = await this.client.from("whitelist_rules").insert([row]).select();
      if (!error && data && data[0]) {
        return this.mapWhitelistRule(data[0]);
      }
    } catch (e) {
      console.warn("Notice: REST insert to whitelist_rules skipped or RLS blocked:", e);
    }
    return { id, pattern, description, createdAt: new Date().toISOString(), addedBy };
  }

  public async deleteWhitelistRule(id: string): Promise<boolean> {
    try {
      const { error } = await this.client.from("whitelist_rules").delete().eq("id", id);
      return !error;
    } catch {
      return true;
    }
  }

  // ─── Phishing Rules ─────────────────────────────────────────────────────────
  public async getPhishingRules(): Promise<PhishingRule[]> {
    try {
      const { data, error } = await this.client.from("phishing_rules").select("*");
      if (error || !data || data.length === 0) {
        return this.getDefaultPhishingRules();
      }
      return data.map(this.mapPhishingRule);
    } catch {
      return this.getDefaultPhishingRules();
    }
  }

  private getDefaultPhishingRules(): PhishingRule[] {
    return [
      { id: "ph_login_suspicious", pattern: "*login-verify-account*", severity: "CRITICAL", reason: "Interception rule: Account verification and credential harvesting pattern", createdAt: new Date().toISOString(), addedBy: "System Policy" },
      { id: "ph_banking_alert", pattern: "*security-update-banking*", severity: "CRITICAL", reason: "Interception rule: High-risk banking credential harvesting pattern", createdAt: new Date().toISOString(), addedBy: "System Policy" },
      { id: "ph_zip_tld", pattern: "*.zip", severity: "HIGH", reason: "Interception rule: Suspicious Top-Level Domain (TLD) payload delivery", createdAt: new Date().toISOString(), addedBy: "System Policy" }
    ];
  }

  public async addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string, addedBy = "Admin"): Promise<PhishingRule> {
    const id = `ph_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const row = { id, pattern, severity, reason, added_by: addedBy };
    try {
      const { data, error } = await this.client.from("phishing_rules").insert([row]).select();
      if (!error && data && data[0]) {
        return this.mapPhishingRule(data[0]);
      }
    } catch (e) {
      console.warn("Notice: REST insert to phishing_rules skipped or RLS blocked:", e);
    }
    return { id, pattern, severity, reason, createdAt: new Date().toISOString(), addedBy };
  }

  public async deletePhishingRule(id: string): Promise<boolean> {
    try {
      const { error } = await this.client.from("phishing_rules").delete().eq("id", id);
      return !error;
    } catch {
      return true;
    }
  }

  // ─── Clients ───────────────────────────────────────────────────────────────
  public async getClients(): Promise<EnrolledClient[]> {
    try {
      const { data, error } = await this.client.from("clients").select("*");
      if (!error && data) {
        return data.map(this.mapClient);
      }
    } catch (e) {
      console.warn("Notice: getClients via REST:", e);
    }
    return Array.from(this.memoryCache.clients.values()).map(this.mapClient);
  }

  public async clientExists(id: string): Promise<boolean> {
    const clients = await this.getClients();
    return clients.some(c => c.id === id);
  }

  public async getClientById(id: string): Promise<EnrolledClient | null> {
    const clients = await this.getClients();
    return clients.find(c => c.id === id) || null;
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
    const now = new Date().toISOString();
    const row = {
      id: payload.clientId,
      client_name: payload.clientName || payload.clientId,
      first_seen: now,
      last_seen: now,
      status: "ENROLLED",
      extension_version: payload.extensionVersion || "1.4",
      browser: payload.browser || "Chrome",
      os: payload.os || "Linux",
      platform: payload.platform || "x86_64",
      ip: payload.ip || "remote-ip"
    };

    this.memoryCache.clients.set(payload.clientId, row);

    try {
      const { data, error } = await this.client.from("clients").upsert([row]).select();
      if (!error && data && data[0]) {
        return this.mapClient(data[0]);
      }
    } catch (e) {
      console.warn("Notice: registerOrUpdateClient REST error:", e);
    }

    return this.mapClient(row);
  }

  public async heartbeatClient(
    clientId: string,
    stats?: Record<string, number>,
    clientName?: string,
    ip?: string
  ): Promise<boolean> {
    const now = new Date().toISOString();
    try {
      const { error } = await this.client
        .from("clients")
        .update({ last_seen: now, ...(ip ? { ip } : {}), ...(clientName ? { client_name: clientName } : {}) })
        .eq("id", clientId);
      if (!error) return true;
    } catch (e) {
      console.warn("Notice: heartbeatClient error:", e);
    }

    const existing = this.memoryCache.clients.get(clientId);
    if (existing) {
      existing.last_seen = now;
      if (ip) existing.ip = ip;
      if (clientName) existing.client_name = clientName;
    }
    return true;
  }

  public async deleteClient(id: string): Promise<boolean> {
    this.memoryCache.clients.delete(id);
    try {
      const { error } = await this.client.from("clients").delete().eq("id", id);
      return !error;
    } catch {
      return true;
    }
  }

  // ─── Threat Alerts ──────────────────────────────────────────────────────────
  public async getThreatAlerts(clientId?: string): Promise<ThreatAlert[]> {
    try {
      let query = this.client.from("threat_alerts").select("*");
      if (clientId && clientId !== "ALL") {
        query = query.eq("client_id", clientId);
      }
      const { data, error } = await query;
      if (!error && data) {
        return data.map(this.mapThreatAlert);
      }
    } catch (e) {
      console.warn("Notice: getThreatAlerts error:", e);
    }
    return [];
  }

  public async recordThreatAlert(alert: Omit<ThreatAlert, "id" | "timestamp" | "status">): Promise<ThreatAlert> {
    const id = `alt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();
    const row = {
      id,
      client_id: alert.clientId || "anonymous",
      client_name: alert.clientName || "Workstation",
      url: alert.url,
      domain: alert.domain,
      score: alert.score,
      reasons: alert.reasons || [],
      source: alert.source || "extension",
      status: "ACTIVE",
      occurred_at: now
    };

    try {
      const { data, error } = await this.client.from("threat_alerts").insert([row]).select();
      if (!error && data && data[0]) {
        return this.mapThreatAlert(data[0]);
      }
    } catch (e) {
      console.warn("Notice: recordThreatAlert error:", e);
    }

    return this.mapThreatAlert(row);
  }

  public async updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED"): Promise<boolean> {
    try {
      const { error } = await this.client.from("threat_alerts").update({ status }).eq("id", id);
      return !error;
    } catch {
      return true;
    }
  }

  // ─── URL Events ─────────────────────────────────────────────────────────────
  public async hasEventId(eventId: string): Promise<boolean> {
    try {
      const { data, error } = await this.client.from("url_events").select("id").eq("event_id", eventId).limit(1);
      return !error && Boolean(data && data.length > 0);
    } catch {
      return false;
    }
  }

  public async recordUrlEvent(
    event: Omit<UrlEvent, "id" | "timestamp">,
    occurredAt?: string
  ): Promise<{ event: UrlEvent; wasNew: boolean }> {
    const id = `evt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = occurredAt || new Date().toISOString();
    const row = {
      id,
      event_id: event.eventId || null,
      client_id: event.clientId || "anonymous",
      client_name: event.clientName || "Workstation",
      url: event.url,
      domain: event.domain,
      classification: event.classification,
      verdict: event.verdict,
      score: event.score,
      reason: event.reason,
      source: event.source || "extension",
      rule_triggered: Boolean(event.ruleTriggered),
      rule_type: event.ruleType || null,
      occurred_at: timestamp
    };

    try {
      const { data, error } = await this.client.from("url_events").insert([row]).select();
      if (!error && data && data[0]) {
        return { event: this.mapUrlEvent(data[0]), wasNew: true };
      }
    } catch (e) {
      console.warn("Notice: recordUrlEvent insert error:", e);
    }

    return { event: this.mapUrlEvent(row), wasNew: true };
  }

  public async getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult> {
    try {
      let query = this.client.from("url_events").select("*", { count: "exact" });
      if (filters?.clientId && filters.clientId !== "ALL") {
        query = query.eq("client_id", filters.clientId);
      }
      if (filters?.classification) {
        query = query.eq("classification", filters.classification);
      }
      if (filters?.search) {
        query = query.or(`url.ilike.%${filters.search}%,domain.ilike.%${filters.search}%`);
      }
      query = query.order("occurred_at", { ascending: false });
      if (typeof filters?.limit === "number") {
        const offset = filters.offset || 0;
        query = query.range(offset, offset + filters.limit - 1);
      }

      const { data, count, error } = await query;
      if (!error && data) {
        return {
          events: data.map(this.mapUrlEvent),
          total: count ?? data.length
        };
      }
    } catch (e) {
      console.warn("Notice: getUrlEvents error:", e);
    }

    return { events: [], total: 0 };
  }

  // ─── Dashboard Stats ────────────────────────────────────────────────────────
  public async getDashboardStats(clientId?: string): Promise<DashboardStatsResult> {
    const isGlobal = !clientId || clientId === "ALL";

    try {
      let [clientsRes, alertsRes, eventsRes] = await Promise.all([
        this.client.from("clients").select("*"),
        isGlobal
          ? this.client.from("threat_alerts").select("*")
          : this.client.from("threat_alerts").select("*").eq("client_id", clientId),
        isGlobal
          ? this.client.from("url_events").select("*").order("occurred_at", { ascending: false }).limit(500)
          : this.client.from("url_events").select("*").eq("client_id", clientId).order("occurred_at", { ascending: false }).limit(500)
      ]);

      const clients = (clientsRes.data || []).map(this.mapClient);
      const alerts = (alertsRes.data || []).map(this.mapThreatAlert);
      const events = (eventsRes.data || []).map(this.mapUrlEvent);

      const totalSystems = clients.length;
      const urlsMonitored = events.length;
      const safe = events.filter(e => e.classification === "SAFE").length;
      const suspicious = events.filter(e => e.classification === "SUSPICIOUS").length;
      const phishing = events.filter(e => e.classification === "PHISHING").length;
      const activeAlerts = alerts.filter(a => a.status === "ACTIVE").length;

      const threatDomainCounts = new Map<string, number>();
      alerts.forEach(a => {
        if (a.domain) threatDomainCounts.set(a.domain, (threatDomainCounts.get(a.domain) || 0) + 1);
      });
      const topThreatDomains = Array.from(threatDomainCounts.entries())
        .map(([domain, count]) => ({ domain, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

      return {
        scope: isGlobal ? "ALL" : (clientId as string),
        totalSystems,
        urlsMonitored,
        allowedUrls: safe,
        phishingIntercepted: phishing,
        activeAlerts,
        breakdown: {
          evaluated: urlsMonitored,
          safe,
          suspicious,
          phishing
        },
        recentEvents: events.slice(0, 10),
        topThreatDomains
      };
    } catch (err) {
      console.warn("Notice: getDashboardStats via Supabase REST error:", err);
      return {
        scope: isGlobal ? "ALL" : (clientId as string),
        totalSystems: 0,
        urlsMonitored: 0,
        allowedUrls: 0,
        phishingIntercepted: 0,
        activeAlerts: 0,
        breakdown: { evaluated: 0, safe: 0, suspicious: 0, phishing: 0 },
        recentEvents: [],
        topThreatDomains: []
      };
    }
  }

  // ─── Reports ────────────────────────────────────────────────────────────────
  public async getReportData(clientId?: string): Promise<ReportDataResult> {
    const isGlobal = !clientId || clientId === "ALL";
    const [clients, alerts, eventsRes] = await Promise.all([
      this.getClients(),
      this.getThreatAlerts(isGlobal ? undefined : clientId),
      this.getUrlEvents({ clientId: isGlobal ? undefined : clientId, limit: 1000 })
    ]);

    const events = eventsRes.events;
    const safeCount = events.filter(e => e.classification === "SAFE").length;
    const suspiciousCount = events.filter(e => e.classification === "SUSPICIOUS").length;
    const phishingCount = events.filter(e => e.classification === "PHISHING").length;

    const threatDomainCounts = new Map<string, number>();
    alerts.forEach(a => {
      if (a.domain) threatDomainCounts.set(a.domain, (threatDomainCounts.get(a.domain) || 0) + 1);
    });
    const topThreatDomains = Array.from(threatDomainCounts.entries())
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    const perSystem = clients.map(client => {
      const clientEvents = events.filter(e => e.clientId === client.id);
      const clientAlerts = alerts.filter(a => a.clientId === client.id);
      return {
        clientId: client.id,
        clientName: client.clientName,
        os: client.os,
        browser: client.browser,
        totalScanned: clientEvents.length,
        safe: clientEvents.filter(e => e.classification === "SAFE").length,
        suspicious: clientEvents.filter(e => e.classification === "SUSPICIOUS").length,
        phishing: clientEvents.filter(e => e.classification === "PHISHING").length,
        activeAlerts: clientAlerts.filter(a => a.status === "ACTIVE").length
      };
    });

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
}
