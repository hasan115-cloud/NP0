import { DashboardStats, EnrolledClient, PhishingRule, ReportData, ThreatAlert, UrlEvent, WhitelistRule } from "./types";

export async function fetchStats(clientId?: string): Promise<DashboardStats> {
  // Scoped with the same clientId the URL History table uses, so both views
  // are always computed from the identical server-side record set.
  const query = clientId && clientId !== "ALL" ? `?clientId=${encodeURIComponent(clientId)}` : "";
  const res = await fetch(`/api/stats${query}`);
  if (!res.ok) throw new Error("Failed to load dashboard stats");
  return res.json();
}

export async function fetchClients(): Promise<EnrolledClient[]> {
  const res = await fetch("/api/clients");
  if (!res.ok) throw new Error("Failed to load enrolled clients");
  const data = await res.json();
  return data.clients || [];
}

export async function fetchClientDetails(id: string): Promise<{ client: EnrolledClient; events: UrlEvent[]; alerts: ThreatAlert[] }> {
  const res = await fetch(`/api/clients/${id}`);
  if (!res.ok) throw new Error("Failed to load client details");
  return res.json();
}

export async function deleteClient(id: string): Promise<boolean> {
  const res = await fetch(`/api/clients/${id}`, {
    method: "DELETE"
  });
  return res.ok;
}

export async function fetchEvents(params?: {
  clientId?: string;
  classification?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<{ events: UrlEvent[]; total: number }> {
  const query = new URLSearchParams();
  if (params?.clientId && params.clientId !== "ALL") query.set("clientId", params.clientId);
  if (params?.classification && params.classification !== "ALL") query.set("classification", params.classification);
  if (params?.search) query.set("search", params.search);
  if (params?.limit) query.set("limit", params.limit.toString());
  if (params?.offset) query.set("offset", params.offset.toString());

  const res = await fetch(`/api/events?${query.toString()}`);
  if (!res.ok) throw new Error("Failed to load URL history");
  return res.json();
}

export async function fetchThreatAlerts(clientId?: string): Promise<ThreatAlert[]> {
  const query = clientId && clientId !== "ALL" ? `?clientId=${clientId}` : "";
  const res = await fetch(`/api/threats${query}`);
  if (!res.ok) throw new Error("Failed to load threat alerts");
  const data = await res.json();
  return data.alerts || [];
}

export async function updateAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED"): Promise<boolean> {
  const res = await fetch(`/api/threats/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status })
  });
  return res.ok;
}

export async function fetchRules(): Promise<{ whitelist: WhitelistRule[]; phishing: PhishingRule[] }> {
  const res = await fetch("/api/rules");
  if (!res.ok) throw new Error("Failed to load rules");
  return res.json();
}

export async function addWhitelistRule(pattern: string, description: string): Promise<WhitelistRule> {
  const res = await fetch("/api/rules/whitelist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pattern, description })
  });
  if (!res.ok) throw new Error("Failed to add whitelist rule");
  const data = await res.json();
  return data.rule;
}

export async function deleteWhitelistRule(id: string): Promise<boolean> {
  const res = await fetch(`/api/rules/whitelist/${id}`, { method: "DELETE" });
  return res.ok;
}

export async function addPhishingRule(pattern: string, severity: "HIGH" | "CRITICAL", reason: string): Promise<PhishingRule> {
  const res = await fetch("/api/rules/phishing", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pattern, severity, reason })
  });
  if (!res.ok) throw new Error("Failed to add phishing rule");
  const data = await res.json();
  return data.rule;
}

export async function deletePhishingRule(id: string): Promise<boolean> {
  const res = await fetch(`/api/rules/phishing/${id}`, { method: "DELETE" });
  return res.ok;
}

export async function fetchServerInfo(): Promise<{
  serverUrl: string;
  version: string;
  status: string;
  database?: string;
  databaseHost?: string;
}> {
  const res = await fetch("/api/info");
  if (!res.ok) throw new Error("Failed to load server info");
  return res.json();
}

export async function fetchReportData(clientId?: string): Promise<ReportData> {
  const query = clientId && clientId !== "ALL" ? `?clientId=${encodeURIComponent(clientId)}` : "";
  const res = await fetch(`/api/reports${query}`);
  if (!res.ok) throw new Error("Failed to load report data");
  return res.json();
}

export function getDownloadExtensionUrl(): string {
  return "/api/download-extension";
}
