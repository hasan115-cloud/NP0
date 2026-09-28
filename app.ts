import express from "express";
import cors from "cors";
import { db } from "./db";
import { classifyUrl } from "./detector";
import { generateExtensionZip } from "./extensionPackager";

export function createApiApp() {
  const app = express();

  // CORS configuration to accept Chrome Extension requests from any client origin
  app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Client-ID"]
  }));

  app.use(express.json({ limit: "10mb" }));

  // Helper to determine the public server URL from headers or fallback
  const getPublicServerUrl = (req: express.Request): string => {
    if (process.env.APP_URL) {
      return process.env.APP_URL.replace(/\/$/, "");
    }
    const forwardedProto = req.get("x-forwarded-proto") || req.protocol;
    const host = req.get("host") || "localhost:3000";
    return `${forwardedProto}://${host}`;
  };

  const router = express.Router();

  // Health check
  router.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      service: "PhishGuard Enterprise Security Hub",
      timestamp: new Date().toISOString()
    });
  });

  // Server Info & Config
  router.get("/info", (req, res) => {
    res.json({
      serverUrl: getPublicServerUrl(req),
      version: "1.4.0",
      status: "operational",
      // Surfaces the storage-consistency caveat directly in the API so it's
      // diagnosable from the dashboard/extension instead of silently causing
      // "sometimes complete, sometimes not" symptoms with no explanation.
      persistenceWarning: db.isPossiblyEphemeralDeployment()
        ? "This process is running in a serverless-style environment (NETLIFY/AWS_LAMBDA_FUNCTION_NAME detected). Local disk storage is not guaranteed to be shared or persistent across function instances — run this server as a single long-lived process for guaranteed data consistency."
        : null
    });
  });

  // Extension ZIP Download Endpoint
  router.get(["/download-extension", "/extension/download"], async (req, res) => {
    try {
      const serverUrl = getPublicServerUrl(req);
      const zipBuffer = await generateExtensionZip(serverUrl);

      res.setHeader("Content-Type", "application/zip");
      res.setHeader("Content-Disposition", 'attachment; filename="phishguard-extension.zip"');
      res.setHeader("Content-Length", zipBuffer.length);
      res.send(zipBuffer);
    } catch (error: any) {
      console.error("Error packaging extension:", error);
      res.status(500).json({ error: "Failed to generate extension package", message: error?.message });
    }
  });

  // Client Registration & Heartbeat
  router.post("/clients/register", async (req, res) => {
    const { clientId, clientName, os, browser, platform, extensionVersion } = req.body;
    if (!clientId) {
      return res.status(400).json({ error: "clientId is required" });
    }

    const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress || "unknown";

    try {
      const client = await db.registerOrUpdateClient({
        clientId,
        clientName,
        os,
        browser,
        platform,
        extensionVersion,
        ip
      });

      const [whitelist, phishing] = await Promise.all([db.getWhitelistRules(), db.getPhishingRules()]);

      res.json({
        success: true,
        client,
        rules: { whitelist, phishing },
        serverTime: new Date().toISOString()
      });
    } catch (error: any) {
      console.error("clients/register error:", error);
      res.status(500).json({ error: "Failed to register client", message: error?.message });
    }
  });

  router.post("/clients/heartbeat", async (req, res) => {
    const { clientId, stats, clientName } = req.body;
    if (!clientId) {
      return res.status(400).json({ error: "clientId is required" });
    }

    const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress;
    try {
      await db.heartbeatClient(clientId, stats, clientName, ip);
      const [whitelist, phishing] = await Promise.all([db.getWhitelistRules(), db.getPhishingRules()]);

      res.json({
        success: true,
        rules: { whitelist, phishing },
        serverTime: new Date().toISOString()
      });
    } catch (error: any) {
      console.error("clients/heartbeat error:", error);
      res.status(500).json({ error: "Failed to record heartbeat", message: error?.message });
    }
  });

  router.get("/clients", async (_req, res) => {
    try {
      const clients = await db.getClients();
      res.json({ clients, count: clients.length });
    } catch (error: any) {
      console.error("GET /clients error:", error);
      res.status(500).json({ error: "Failed to load clients", message: error?.message });
    }
  });

  router.get("/clients/:id", async (req, res) => {
    try {
      const client = await db.getClientById(req.params.id);
      if (!client) {
        return res.status(404).json({ error: "Client not found" });
      }
      // No limit: this system's complete stored history, same source of
      // truth as /events, so a drill-down can never show fewer records
      // than the URL History table does for the same system.
      const [{ events }, alerts] = await Promise.all([
        db.getUrlEvents({ clientId: req.params.id }),
        db.getThreatAlerts(req.params.id)
      ]);
      res.json({ client, events, alerts });
    } catch (error: any) {
      console.error("GET /clients/:id error:", error);
      res.status(500).json({ error: "Failed to load client", message: error?.message });
    }
  });

  router.delete("/clients/:id", async (req, res) => {
    try {
      const success = await db.deleteClient(req.params.id);
      if (!success) {
        return res.status(404).json({ error: "Client not found" });
      }
      res.json({ success: true, message: "System unenrolled and removed from database" });
    } catch (error: any) {
      console.error("DELETE /clients/:id error:", error);
      res.status(500).json({ error: "Failed to delete client", message: error?.message });
    }
  });

  // Real URL Scanning & Telemetry Relay
  router.post("/scan", async (req, res) => {
    const { url, source = "extension", clientId = "anonymous", clientName = "Workstation", eventId } = req.body;
    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    try {
      // Auto-enroll client if communicating with server
      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress;
        await db.registerOrUpdateClient({ clientId, clientName, ip });
      }

      const result = await classifyUrl(url);

      await db.recordUrlEvent({
        // Optional idempotency key: when the extension supplies one, a
        // retried scan of the same observation updates nothing instead of
        // appending a second identical history row.
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
        ruleType: result.ruleType || null
      });

      if (result.verdict === "PHISHING") {
        await db.recordThreatAlert({
          clientId,
          clientName,
          url,
          domain: result.domain,
          score: result.score,
          reasons: result.reasons,
          source
        });
      }

      res.json({
        verdict: result.verdict,
        action: result.action,
        score: result.score,
        risk_score: result.score,
        domain: result.domain,
        reasons: result.reasons,
        whitelisted: result.whitelisted,
        policyMatched: result.policyMatched
      });
    } catch (error: any) {
      // A successful HTTP response is the extension's ONLY signal that an
      // event was durably persisted (it queues for retry on anything
      // else), so a storage failure must surface as an error response,
      // never as a fabricated 200 — otherwise a real record silently never
      // gets written AND never gets retried.
      console.error("POST /scan error:", error);
      res.status(500).json({ error: "Failed to record scan", message: error?.message });
    }
  });

  router.post("/bulk-scan", async (req, res) => {
    const { urls, eventIds, source = "extension-bulk", clientId = "anonymous", clientName = "Workstation" } = req.body;
    if (!Array.isArray(urls)) {
      return res.status(400).json({ error: "urls array is required" });
    }
    // Optional per-URL idempotency keys, positionally aligned with `urls`.
    const ids: (string | undefined)[] = Array.isArray(eventIds) ? eventIds : [];

    try {
      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress;
        await db.registerOrUpdateClient({ clientId, clientName, ip });
      }

      // Classify and persist each URL independently, in parallel — each
      // write is its own row, so one URL's failure doesn't block or corrupt
      // the others' results.
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
            ruleType: result.ruleType || null
          });

          if (result.verdict === "PHISHING") {
            await db.recordThreatAlert({
              clientId,
              clientName,
              url: u,
              domain: result.domain,
              score: result.score,
              reasons: result.reasons,
              source
            });
          }

          return {
            url: u,
            verdict: result.verdict,
            score: result.score,
            risk_score: result.score,
            domain: result.domain,
            reasons: result.reasons
          };
        })
      );

      res.json({ results });
    } catch (error: any) {
      console.error("POST /bulk-scan error:", error);
      res.status(500).json({ error: "Failed to record bulk scan", message: error?.message });
    }
  });

  // Threat Alerts
  router.post("/threats/alert", async (req, res) => {
    const { clientId, clientName, url, domain, score, reasons, source } = req.body;
    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    try {
      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress;
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
        source: source || "extension-block"
      });

      res.json({ success: true, alert });
    } catch (error: any) {
      console.error("POST /threats/alert error:", error);
      res.status(500).json({ error: "Failed to record threat alert", message: error?.message });
    }
  });

  router.get("/threats", async (req, res) => {
    try {
      const clientId = req.query.clientId as string | undefined;
      const alerts = await db.getThreatAlerts(clientId);
      res.json({ alerts, count: alerts.length });
    } catch (error: any) {
      console.error("GET /threats error:", error);
      res.status(500).json({ error: "Failed to load threat alerts", message: error?.message });
    }
  });

  router.patch("/threats/:id", async (req, res) => {
    const { status } = req.body;
    if (!status || !["ACKNOWLEDGED", "RESOLVED"].includes(status)) {
      return res.status(400).json({ error: "Valid status required" });
    }
    try {
      const ok = await db.updateThreatAlertStatus(req.params.id, status);
      if (!ok) return res.status(404).json({ error: "Alert not found" });
      res.json({ success: true });
    } catch (error: any) {
      console.error("PATCH /threats/:id error:", error);
      res.status(500).json({ error: "Failed to update alert", message: error?.message });
    }
  });

  // Rules & Policies
  router.get("/rules", async (_req, res) => {
    try {
      const [whitelist, phishing] = await Promise.all([db.getWhitelistRules(), db.getPhishingRules()]);
      res.json({ whitelist, phishing });
    } catch (error: any) {
      console.error("GET /rules error:", error);
      res.status(500).json({ error: "Failed to load rules", message: error?.message });
    }
  });

  router.post("/rules/whitelist", async (req, res) => {
    const { pattern, description } = req.body;
    if (!pattern) return res.status(400).json({ error: "Pattern is required" });
    try {
      const rule = await db.addWhitelistRule(pattern, description || "Whitelisted domain");
      res.json({ success: true, rule });
    } catch (error: any) {
      console.error("POST /rules/whitelist error:", error);
      res.status(500).json({ error: "Failed to add whitelist rule", message: error?.message });
    }
  });

  router.delete("/rules/whitelist/:id", async (req, res) => {
    try {
      const ok = await db.deleteWhitelistRule(req.params.id);
      if (!ok) return res.status(404).json({ error: "Rule not found" });
      res.json({ success: true });
    } catch (error: any) {
      console.error("DELETE /rules/whitelist/:id error:", error);
      res.status(500).json({ error: "Failed to delete whitelist rule", message: error?.message });
    }
  });

  router.post("/rules/phishing", async (req, res) => {
    const { pattern, severity = "HIGH", reason } = req.body;
    if (!pattern) return res.status(400).json({ error: "Pattern is required" });
    try {
      const rule = await db.addPhishingRule(pattern, severity, reason || "Threat rule");
      res.json({ success: true, rule });
    } catch (error: any) {
      console.error("POST /rules/phishing error:", error);
      res.status(500).json({ error: "Failed to add phishing rule", message: error?.message });
    }
  });

  router.delete("/rules/phishing/:id", async (req, res) => {
    try {
      const ok = await db.deletePhishingRule(req.params.id);
      if (!ok) return res.status(404).json({ error: "Rule not found" });
      res.json({ success: true });
    } catch (error: any) {
      console.error("DELETE /rules/phishing/:id error:", error);
      res.status(500).json({ error: "Failed to delete phishing rule", message: error?.message });
    }
  });

  // Dashboard Stats & URL History
  //
  // Accepts the same clientId scope as /events, so the Overview counts and
  // the URL History table are always computed from the SAME record set.
  // Without this the Overview was fleet-wide while History was per-system,
  // which is why the two views showed different numbers for one machine.
  router.get("/stats", async (req, res) => {
    try {
      const clientId = req.query.clientId as string | undefined;
      const stats = await db.getDashboardStats(clientId);
      res.json(stats);
    } catch (error: any) {
      console.error("GET /stats error:", error);
      res.status(500).json({ error: "Failed to load dashboard stats", message: error?.message });
    }
  });

  // Strictly-scoped report data (ALL SYSTEMS or a single system/agent).
  // This is the single source of truth for the Reports view and PDF/Print
  // export, guaranteeing a single-system report can never contain another
  // system's data because filtering happens here, server-side, against the
  // persistent database — never in client-side React state.
  router.get("/reports", async (req, res) => {
    try {
      const clientId = req.query.clientId as string | undefined;
      if (clientId && clientId !== "ALL" && !(await db.clientExists(clientId))) {
        return res.status(404).json({ error: "System not found" });
      }
      const report = await db.getReportData(clientId);
      res.json(report);
    } catch (error: any) {
      console.error("GET /reports error:", error);
      res.status(500).json({ error: "Failed to load report data", message: error?.message });
    }
  });

  // ─── Batch URL-event ingest (extension telemetry + offline queue) ───────
  //
  // This is the endpoint that makes history COMPLETE. The extension decides
  // many verdicts locally and instantly — administrator rule matches, known
  // safe apex domains, user-trusted domains, and its 15-minute verdict
  // cache — and in every one of those cases it used to return without ever
  // contacting the server, so the visit was never recorded anywhere. Those
  // navigations really happened and must appear in history, so the
  // extension now reports every observed navigation here regardless of how
  // its verdict was reached.
  //
  // Properties that matter:
  //  - Idempotent. Each event carries a client-minted eventId; re-sending
  //    one that already landed is counted as a duplicate and dropped, so
  //    the offline queue can retry freely without creating double rows.
  //  - Merge-only. It appends; it never replaces or truncates stored
  //    history, so a batch arriving late can't wipe out earlier records.
  //  - Server-authoritative classification. The verdict is recomputed here
  //    from the server's own rules and heuristics rather than trusted from
  //    the client, so the stored classification (and therefore every
  //    Overview count) always reflects current server policy.
  router.post("/url-events", async (req, res) => {
    const { clientId = "anonymous", clientName = "Workstation", events } = req.body;

    if (!Array.isArray(events)) {
      return res.status(400).json({ error: "events array is required" });
    }

    try {
      if (clientId && clientId !== "anonymous" && !(await db.clientExists(clientId))) {
        const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress;
        await db.registerOrUpdateClient({ clientId, clientName, ip });
      }

      let accepted = 0;
      let duplicates = 0;
      let invalid = 0;
      let failed = 0;
      const acceptedIds: string[] = [];
      const duplicateIds: string[] = [];

      // Sequential, not parallel: this batch can be large (the extension
      // flushes up to a few hundred queued events at once), and processing
      // one at a time keeps the acceptedIds/duplicateIds accounting exactly
      // right without needing extra synchronization. Each event is its own
      // durable write — one failing does not roll back or block any other,
      // so a partial failure still returns every id that DID land.
      for (const incoming of events) {
        const url = incoming?.url;
        const eventId = incoming?.eventId;

        if (!url || typeof url !== "string" || !eventId || typeof eventId !== "string") {
          invalid++;
          continue;
        }

        try {
          // No separate pre-check here on purpose: db.hasEventId() followed
          // by db.recordUrlEvent() would be a "check, then write" pattern —
          // exactly the race that let two concurrent requests (from two
          // different instances, or two interleaved requests on one) both
          // see "not present yet" and both report themselves as the
          // accepted write, even though the database correctly stored only
          // one row. recordUrlEvent's own `wasNew` flag comes from the same
          // atomic operation that performed the write, so it's the only
          // trustworthy signal — even under real concurrent writes for the
          // same eventId from separate instances.
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
              ruleType: result.ruleType || null
            },
            typeof incoming.observedAt === "string" ? incoming.observedAt : undefined
          );

          if (wasNew) {
            accepted++;
            acceptedIds.push(eventId);

            // AUDIT FIX: /scan and /bulk-scan both raise a Threat Alert the
            // moment a PHISHING verdict is recorded, but this batch path —
            // which is the extension's PRIMARY channel, since it is the one
            // used for every navigation whose verdict was resolved locally
            // (rule matches, cached verdicts, safe-apex short-circuits) —
            // previously did not. That silently meant most real phishing
            // detections in production never appeared in the Threat Alerts
            // view or its count, even though they were correctly stored in
            // history and counted in the Overview breakdown. Gated on
            // `wasNew` so a retried/duplicate delivery of the same eventId
            // (the offline queue's whole reason for existing) can never
            // create a second alert for one detection.
            if (result.verdict === "PHISHING") {
              await db.recordThreatAlert({
                clientId,
                clientName,
                url,
                domain: result.domain,
                score: result.score,
                reasons: result.reasons,
                source: typeof incoming.source === "string" ? incoming.source : "extension-navigation"
              });
            }
          } else {
            duplicates++;
            duplicateIds.push(eventId);
          }
        } catch (perEventError) {
          // This one event failed to persist — do NOT add its id to
          // acknowledgedIds, so the extension keeps it queued and retries
          // it later rather than treating an unwritten event as delivered.
          failed++;
          console.error(`url-events: failed to persist eventId=${eventId}:`, perEventError);
        }
      }

      // acceptedIds + duplicateIds is what the extension may safely drop
      // from its local queue: both are confirmed durable on the server.
      // Anything that failed stays out of this list on purpose, so it's
      // retried on the next flush instead of being silently dropped.
      res.json({
        success: true,
        accepted,
        duplicates,
        invalid,
        failed,
        acknowledgedIds: [...acceptedIds, ...duplicateIds]
      });
    } catch (error: any) {
      console.error("POST /url-events error:", error);
      res.status(500).json({ error: "Failed to record URL events", message: error?.message });
    }
  });

  router.get("/events", async (req, res) => {
    try {
      const { clientId, classification, search, limit, offset } = req.query;
      const result = await db.getUrlEvents({
        clientId: clientId as string,
        classification: classification as string,
        search: search as string,
        // No default cap: the dashboard's URL History expects the complete,
        // accurate history in one load. Only apply a limit when the caller
        // explicitly asks for one (e.g. future paging).
        limit: limit ? parseInt(limit as string) : undefined,
        offset: offset ? parseInt(offset as string) : 0
      });
      res.json(result);
    } catch (error: any) {
      console.error("GET /events error:", error);
      res.status(500).json({ error: "Failed to load URL history", message: error?.message });
    }
  });

  // Mount router at both "/api" (for standard requests) and "/" (for Netlify redirects)
  app.use("/api", router);
  app.use("/", router);

  return app;
}
