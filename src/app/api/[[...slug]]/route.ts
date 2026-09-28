import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { classifyUrl } from "@/lib/detector";
import { generateExtensionZip } from "@/lib/extensionPackager";

const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-ID",
};

function json(data: any, status = 200) {
  return NextResponse.json(data, {
    status,
    headers: corsHeaders,
  });
}

function getPublicServerUrl(req: NextRequest): string {
  if (process.env.APP_URL) {
    return process.env.APP_URL.replace(/\/$/, "");
  }
  const host = req.headers.get("host") || "localhost:3000";
  const proto = req.headers.get("x-forwarded-proto") || "http";
  return `${proto}://${host}`;
}

function getClientIp(req: NextRequest): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return "unknown";
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders,
  });
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ slug?: string[] }> }
) {
  const resolved = await params;
  const slug = resolved.slug || [];
  const p0 = slug[0] || "";
  const p1 = slug[1] || "";

  try {
    // GET /api/health
    if (p0 === "health") {
      return json({
        status: "ok",
        service: "PhishGuard Enterprise Security Hub",
        timestamp: new Date().toISOString(),
      });
    }

    // GET /api/info
    if (p0 === "info") {
      const dbInfo = db.getDatabaseInfo ? db.getDatabaseInfo() : { isSupabase: false, host: "local" };
      return json({
        serverUrl: getPublicServerUrl(req),
        version: "1.4.0",
        status: "operational",
        database: dbInfo.isSupabase ? "supabase" : "local",
        databaseHost: dbInfo.host,
        persistenceWarning: db.isPossiblyEphemeralDeployment()
          ? "This process is running in a serverless-style environment (NETLIFY/AWS_LAMBDA_FUNCTION_NAME detected). Local disk storage is not guaranteed to be shared or persistent across function instances — run this server as a single long-lived process for guaranteed data consistency."
          : null,
      });
    }

    // GET /api/download-extension or /api/extension/download
    if (p0 === "download-extension" || (p0 === "extension" && p1 === "download")) {
      const serverUrl = getPublicServerUrl(req);
      const zipBuffer = await generateExtensionZip(serverUrl);
      return new NextResponse(zipBuffer, {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/zip",
          "Content-Disposition": 'attachment; filename="phishguard-extension.zip"',
          "Content-Length": zipBuffer.length.toString(),
        },
      });
    }

    // GET /api/clients/:id
    if (p0 === "clients" && p1) {
      try {
        const client = await db.getClientById(p1);
        if (!client) {
          return json({ error: "Client not found" }, 404);
        }
        const [{ events }, alerts] = await Promise.all([
          db.getUrlEvents({ clientId: p1 }),
          db.getThreatAlerts(p1),
        ]);
        return json({ client, events, alerts });
      } catch (err) {
        console.warn("Notice: /api/clients/:id fallback:", err);
        return json({ error: "Client query failed" }, 404);
      }
    }

    // GET /api/clients
    if (p0 === "clients") {
      try {
        const clients = await db.getClients();
        return json({ clients, count: clients.length });
      } catch (err) {
        console.warn("Notice: /api/clients fallback:", err);
        return json({ clients: [], count: 0 });
      }
    }

    // GET /api/threats
    if (p0 === "threats") {
      const clientId = req.nextUrl.searchParams.get("clientId") || undefined;
      try {
        const alerts = await db.getThreatAlerts(clientId);
        return json({ alerts, count: alerts.length });
      } catch (err) {
        console.warn("Notice: /api/threats fallback:", err);
        return json({ alerts: [], count: 0 });
      }
    }

    // GET /api/rules
    if (p0 === "rules") {
      try {
        const [whitelist, phishing] = await Promise.all([
          db.getWhitelistRules(),
          db.getPhishingRules(),
        ]);
        return json({ whitelist, phishing });
      } catch (err) {
        console.warn("Notice: /api/rules fallback:", err);
        return json({ whitelist: [], phishing: [] });
      }
    }

    // GET /api/stats
    if (p0 === "stats") {
      const clientId = req.nextUrl.searchParams.get("clientId") || undefined;
      try {
        const stats = await db.getDashboardStats(clientId);
        return json(stats);
      } catch (err: any) {
        console.warn("Notice: /api/stats fallback activated:", err);
        return json({
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
    }

    // GET /api/reports
    if (p0 === "reports") {
      const clientId = req.nextUrl.searchParams.get("clientId") || undefined;
      try {
        if (clientId && clientId !== "ALL" && !(await db.clientExists(clientId))) {
          return json({ error: "System not found" }, 404);
        }
        const report = await db.getReportData(clientId);
        return json(report);
      } catch (err: any) {
        console.warn("Notice: /api/reports fallback activated:", err);
        return json({
          scope: clientId || "ALL",
          generatedAt: new Date().toISOString(),
          systems: [],
          summary: { totalEvaluated: 0, safe: 0, suspicious: 0, phishing: 0, activeAlerts: 0 },
          topThreatDomains: [],
          events: [],
          alerts: [],
          perSystem: []
        });
      }
    }

    // GET /api/events
    if (p0 === "events") {
      const sp = req.nextUrl.searchParams;
      const clientId = sp.get("clientId") || undefined;
      const classification = sp.get("classification") || undefined;
      const search = sp.get("search") || undefined;
      const limit = sp.get("limit") ? parseInt(sp.get("limit")!, 10) : undefined;
      const offset = sp.get("offset") ? parseInt(sp.get("offset")!, 10) : 0;

      try {
        const result = await db.getUrlEvents({
          clientId,
          classification,
          search,
          limit,
          offset,
        });
        return json(result);
      } catch (err) {
        console.warn("Notice: /api/events fallback activated:", err);
        return json({ events: [], total: 0 });
      }
    }

    return json({ error: `Not found: /api/${slug.join("/")}` }, 404);
  } catch (error: any) {
    console.error(`GET /api/${slug.join("/")} error:`, error);
    return json({ error: "Internal server error", message: error?.message }, 500);
  }
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ slug?: string[] }> }
) {
  const resolved = await params;
  const slug = resolved.slug || [];
  const p0 = slug[0] || "";
  const p1 = slug[1] || "";

  try {
    const body = await req.json().catch(() => ({}));

    // POST /api/clients/register
    if (p0 === "clients" && p1 === "register") {
      const { clientId, clientName, os, browser, platform, extensionVersion } = body;
      if (!clientId) {
        return json({ error: "clientId is required" }, 400);
      }
      const ip = getClientIp(req);
      const client = await db.registerOrUpdateClient({
        clientId,
        clientName,
        os,
        browser,
        platform,
        extensionVersion,
        ip,
      });
      const [whitelist, phishing] = await Promise.all([
        db.getWhitelistRules(),
        db.getPhishingRules(),
      ]);
      return json({
        success: true,
        client,
        rules: { whitelist, phishing },
        serverTime: new Date().toISOString(),
      });
    }

    // POST /api/clients/heartbeat
    if (p0 === "clients" && p1 === "heartbeat") {
      const { clientId, stats, clientName } = body;
      if (!clientId) {
        return json({ error: "clientId is required" }, 400);
      }
      const ip = getClientIp(req);
      await db.heartbeatClient(clientId, stats, clientName, ip);
      const [whitelist, phishing] = await Promise.all([
        db.getWhitelistRules(),
        db.getPhishingRules(),
      ]);
      return json({
        success: true,
        rules: { whitelist, phishing },
        serverTime: new Date().toISOString(),
      });
    }

    // POST /api/scan
    if (p0 === "scan") {
      const { url, source = "extension", clientId = "anonymous", clientName = "Workstation", eventId } = body;
      if (!url) {
        return json({ error: "URL is required" }, 400);
      }

      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = getClientIp(req);
        await db.registerOrUpdateClient({ clientId, clientName, ip });
      }

      const result = await classifyUrl(url);

      let recordedEvent: any = null;
      try {
        const rec = await db.recordUrlEvent({
          eventId: typeof eventId === "string" ? eventId : undefined,
          clientId,
          clientName,
          url,
          domain: result.domain,
          classification: result.verdict,
          verdict: result.action,
          score: result.score,
          reason: result.reasons.join("; ") || "Clean analysis",
          source,
          ruleTriggered: Boolean(result.whitelisted || result.policyMatched),
          ruleType: result.ruleType || null,
        });
        recordedEvent = rec?.event;

        if (result.verdict === "PHISHING") {
          await db.recordThreatAlert({
            clientId,
            clientName,
            url,
            domain: result.domain,
            score: result.score,
            reasons: result.reasons,
            source,
          });
        }
      } catch (dbErr) {
        console.warn("Notice: scan event persistence error:", dbErr);
      }

      return json({
        verdict: result.verdict,
        action: result.action,
        score: result.score,
        risk_score: result.score,
        domain: result.domain,
        reasons: result.reasons,
        whitelisted: result.whitelisted,
        policyMatched: result.policyMatched,
      });
    }

    // POST /api/bulk-scan
    if (p0 === "bulk-scan") {
      const { urls, eventIds, source = "extension-bulk", clientId = "anonymous", clientName = "Workstation" } = body;
      if (!Array.isArray(urls)) {
        return json({ error: "urls array is required" }, 400);
      }
      const ids: (string | undefined)[] = Array.isArray(eventIds) ? eventIds : [];

      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = getClientIp(req);
        await db.registerOrUpdateClient({ clientId, clientName, ip });
      }

      const results = await Promise.all(
        urls.map(async (u, i) => {
          const result = await classifyUrl(u);

          await db.recordUrlEvent({
            eventId: typeof ids[i] === "string" ? ids[i] : undefined,
            clientId,
            clientName,
            url: u,
            domain: result.domain,
            classification: result.verdict,
            verdict: result.action,
            score: result.score,
            reason: result.reasons[0] || "Clean heuristics",
            source,
            ruleTriggered: Boolean(result.whitelisted || result.policyMatched),
            ruleType: result.ruleType || null,
          });

          if (result.verdict === "PHISHING") {
            await db.recordThreatAlert({
              clientId,
              clientName,
              url: u,
              domain: result.domain,
              score: result.score,
              reasons: result.reasons,
              source,
            });
          }

          return {
            url: u,
            verdict: result.verdict,
            score: result.score,
            risk_score: result.score,
            domain: result.domain,
            reasons: result.reasons,
          };
        })
      );

      return json({ results });
    }

    // POST /api/threats/alert
    if (p0 === "threats" && p1 === "alert") {
      const { clientId, clientName, url, domain, score, reasons, source } = body;
      if (!url) {
        return json({ error: "URL is required" }, 400);
      }

      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = getClientIp(req);
        await db.registerOrUpdateClient({ clientId, clientName, ip });
      }

      let parsedDomain = domain;
      if (!parsedDomain) {
        try {
          parsedDomain = new URL(url).hostname;
        } catch {
          parsedDomain = url;
        }
      }

      const alert = await db.recordThreatAlert({
        clientId: clientId || "anonymous",
        clientName: clientName || "Agent",
        url,
        domain: parsedDomain,
        score: typeof score === "number" ? score : 0.9,
        reasons: Array.isArray(reasons) ? reasons : ["Phishing site intercepted"],
        source: source || "extension-block",
      });

      return json({ success: true, alert });
    }

    // POST /api/rules/whitelist
    if (p0 === "rules" && p1 === "whitelist") {
      const { pattern, description } = body;
      if (!pattern) return json({ error: "Pattern is required" }, 400);
      const rule = await db.addWhitelistRule(pattern, description || "Whitelisted domain");
      return json({ success: true, rule });
    }

    // POST /api/rules/phishing
    if (p0 === "rules" && p1 === "phishing") {
      const { pattern, severity = "HIGH", reason } = body;
      if (!pattern) return json({ error: "Pattern is required" }, 400);
      const rule = await db.addPhishingRule(pattern, severity, reason || "Threat rule");
      return json({ success: true, rule });
    }

    // POST /api/url-events (Batch telemetry ingest)
    if (p0 === "url-events") {
      const { clientId = "anonymous", clientName = "Workstation", events } = body;
      if (!Array.isArray(events)) {
        return json({ error: "events array is required" }, 400);
      }

      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = getClientIp(req);
        await db.registerOrUpdateClient({ clientId, clientName, ip });
      }

      let accepted = 0;
      let duplicates = 0;
      let invalid = 0;
      let failed = 0;
      const acceptedIds: string[] = [];
      const duplicateIds: string[] = [];

      for (const incoming of events) {
        const url = incoming?.url;
        const eventId = incoming?.eventId;

        if (!url || typeof url !== "string" || !eventId || typeof eventId !== "string") {
          invalid++;
          continue;
        }

        try {
          const result = await classifyUrl(url);

          const { wasNew } = await db.recordUrlEvent(
            {
              eventId,
              clientId,
              clientName,
              url,
              domain: result.domain,
              classification: result.verdict,
              verdict: result.action,
              score: result.score,
              reason: result.reasons.join("; ") || "Clean analysis",
              source: typeof incoming.source === "string" ? incoming.source : "extension-navigation",
              ruleTriggered: Boolean(result.whitelisted || result.policyMatched),
              ruleType: result.ruleType || null,
            },
            typeof incoming.observedAt === "string" ? incoming.observedAt : undefined
          );

          if (wasNew) {
            accepted++;
            acceptedIds.push(eventId);

            if (result.verdict === "PHISHING") {
              await db.recordThreatAlert({
                clientId,
                clientName,
                url,
                domain: result.domain,
                score: result.score,
                reasons: result.reasons,
                source: typeof incoming.source === "string" ? incoming.source : "extension-navigation",
              });
            }
          } else {
            duplicates++;
            duplicateIds.push(eventId);
          }
        } catch (perEventError) {
          failed++;
          console.error(`url-events: failed to persist eventId=${eventId}:`, perEventError);
        }
      }

      return json({
        success: true,
        accepted,
        duplicates,
        invalid,
        failed,
        acknowledgedIds: [...acceptedIds, ...duplicateIds],
      });
    }

    return json({ error: `Not found: /api/${slug.join("/")}` }, 404);
  } catch (error: any) {
    console.error(`POST /api/${slug.join("/")} error:`, error);
    return json({ error: "Internal server error", message: error?.message }, 500);
  }
}

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ slug?: string[] }> }
) {
  const resolved = await params;
  const slug = resolved.slug || [];
  const p0 = slug[0] || "";
  const p1 = slug[1] || "";

  try {
    const body = await req.json().catch(() => ({}));

    // PATCH /api/threats/:id
    if (p0 === "threats" && p1) {
      const { status } = body;
      if (!status || !["ACKNOWLEDGED", "RESOLVED"].includes(status)) {
        return json({ error: "Valid status required" }, 400);
      }
      const ok = await db.updateThreatAlertStatus(p1, status);
      if (!ok) return json({ error: "Alert not found" }, 404);
      return json({ success: true });
    }

    return json({ error: `Not found: /api/${slug.join("/")}` }, 404);
  } catch (error: any) {
    console.error(`PATCH /api/${slug.join("/")} error:`, error);
    return json({ error: "Internal server error", message: error?.message }, 500);
  }
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ slug?: string[] }> }
) {
  const resolved = await params;
  const slug = resolved.slug || [];
  const p0 = slug[0] || "";
  const p1 = slug[1] || "";
  const p2 = slug[2] || "";

  try {
    // DELETE /api/clients/:id
    if (p0 === "clients" && p1) {
      const success = await db.deleteClient(p1);
      if (!success) {
        return json({ error: "Client not found" }, 404);
      }
      return json({ success: true, message: "System unenrolled and removed from database" });
    }

    // DELETE /api/rules/whitelist/:id
    if (p0 === "rules" && p1 === "whitelist" && p2) {
      const ok = await db.deleteWhitelistRule(p2);
      if (!ok) return json({ error: "Rule not found" }, 404);
      return json({ success: true });
    }

    // DELETE /api/rules/phishing/:id
    if (p0 === "rules" && p1 === "phishing" && p2) {
      const ok = await db.deletePhishingRule(p2);
      if (!ok) return json({ error: "Rule not found" }, 404);
      return json({ success: true });
    }

    return json({ error: `Not found: /api/${slug.join("/")}` }, 404);
  } catch (error: any) {
    console.error(`DELETE /api/${slug.join("/")} error:`, error);
    return json({ error: "Internal server error", message: error?.message }, 500);
  }
}
