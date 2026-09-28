// PhishGuard Background Service Worker (Manifest V3)
// Client-Server Architecture with Real Telemetry, Enrollment, and Rule Sync

try {
    importScripts("config.js");
} catch (e) {
    console.warn("Could not import config.js in service worker:", e);
}

let BACKEND_URL = "http://localhost:3000";
const CACHE_TTL_MS      = 15 * 60 * 1000;  // 15 min verdict cache
const FETCH_TIMEOUT_MS  = 10 * 1000;        // 10 s per single scan
const BULK_TIMEOUT_MS   = 25 * 1000;        // 25 s for bulk scan
const HEARTBEAT_INTERVAL_MS = 30 * 1000;   // 30 seconds heartbeat

// ─── In-memory state ────────────────────────────────────────────────────────
const verdictCache = new Map();   // url  → { time, data }
const inFlight     = new Map();   // url  → Promise<data>
const bypassedUrls = new Set();   // urls user chose to proceed anyway
const tabStats     = new Map();   // tabId → { total, phishing, suspicious, safe }

// Server-synchronized security rules
let serverWhitelistRules = new Set();
let serverPhishingRules  = new Set();

let clientId = "";
let clientName = "";
let isRegistered = false;

// ─── Apex & Compound SLD Helpers ────────────────────────────────────────────
const _COMPOUND_SLD = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "mil"]);

function apexDomain(url) {
    try {
        const host = new URL(url).hostname.replace(/^www\./, "");
        const parts = host.split(".");
        if (parts.length >= 3) {
            const secondLast = parts[parts.length - 2];
            const last = parts[parts.length - 1];
            if (_COMPOUND_SLD.has(secondLast) && last.length === 2) {
                return parts.slice(-3).join(".");
            }
        }
        return parts.slice(-2).join(".");
    } catch { return ""; }
}

const SAFE_APEX = new Set([
    "google.com","bing.com","yahoo.com","duckduckgo.com","baidu.com","yandex.com",
    "youtube.com","googleapis.com","gstatic.com","googleusercontent.com",
    "microsoft.com","live.com","office.com","azure.com","outlook.com","sharepoint.com",
    "facebook.com","instagram.com","whatsapp.com","twitter.com","x.com",
    "linkedin.com","reddit.com","tiktok.com","snapchat.com","discord.com",
    "github.com","gitlab.com","stackoverflow.com","npmjs.com","cloudflare.com",
    "wikipedia.org","wikimedia.org","amazon.com","apple.com","icloud.com"
]);

// ─── Fetch with timeout ──────────────────────────────────────────────────────
async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
}

// ─── Config & Client Identity ───────────────────────────────────────────────
//
// initServerConfig() is called, guarded by `if (!clientId) await
// initServerConfig()`, from many independent places: registerClient(),
// sendHeartbeat(), scanUrl(), enqueueUrlEvent(), the startup handlers, and
// more. On a cold service-worker start several of these can fire within
// the same tick, before any of them has finished the async
// chrome.storage.local.get() read. Without protection, EACH concurrent
// call would independently see no stored clientId yet, independently
// generate its OWN random id, and independently write it — the last write
// wins in storage, but any network request already sent under one of the
// now-abandoned ids has already registered a genuine DUPLICATE system on
// the server for this one physical install. That is exactly the kind of
// unstable-identity duplication this project must never produce.
//
// _configInitPromise caches the in-flight run: every concurrent caller
// during the same pending window awaits the SAME single execution and
// gets the SAME resolved clientId, so only one id is ever generated per
// cold start. Once resolved, the cache clears, so a later deliberate
// re-init (e.g. the popup's "reconnect" after changing the server URL)
// still runs fresh — and, since storage already holds the persisted id
// by then, it reuses that same stable id rather than minting a new one.
let _configInitPromise = null;
async function initServerConfig() {
    if (_configInitPromise) return _configInitPromise;
    _configInitPromise = (async () => {
    try {
        const defaultConfigUrl = (typeof PHISHGUARD_DEFAULT_CONFIG !== "undefined" && PHISHGUARD_DEFAULT_CONFIG.SERVER_URL)
            ? PHISHGUARD_DEFAULT_CONFIG.SERVER_URL.trim().replace(/\/$/, "")
            : BACKEND_URL;

        const stored = await chrome.storage.local.get(["phishguardServerUrl", "phishguardClientId", "phishguardClientName"]);
        if (stored.phishguardServerUrl && stored.phishguardServerUrl.trim()) {
            BACKEND_URL = stored.phishguardServerUrl.trim().replace(/\/$/, "");
        } else {
            BACKEND_URL = defaultConfigUrl;
            await chrome.storage.local.set({ phishguardServerUrl: BACKEND_URL });
        }

        if (stored.phishguardClientId) {
            clientId = stored.phishguardClientId;
        } else {
            clientId = "pg-client-" + Math.random().toString(36).substring(2, 10) + "-" + Date.now().toString(36);
            await chrome.storage.local.set({ phishguardClientId: clientId });
        }

        if (stored.phishguardClientName) {
            clientName = stored.phishguardClientName;
        } else {
            const platform = (navigator.userAgentData?.platform || navigator.platform || "Workstation").replace(/[^a-zA-Z0-9]/g, "");
            clientName = `${platform}-${clientId.slice(-4).toUpperCase()}`;
            await chrome.storage.local.set({ phishguardClientName: clientName });
        }
    } catch (e) {
        console.warn("Config init error:", e);
    }
    })();
    try {
        await _configInitPromise;
    } finally {
        // Clear the cache once this run settles (success or failure) so a
        // later deliberate call — e.g. the popup's explicit reconnect —
        // still executes fresh, rather than being permanently stuck
        // sharing one run from cold start.
        _configInitPromise = null;
    }
}

function getSystemInfo() {
    const ua = navigator.userAgent;
    let browser = "Chrome";
    const chromeMatch = ua.match(/Chrome\/([0-9.]+)/);
    if (chromeMatch) browser = `Chrome ${chromeMatch[1].split(".")[0]}`;

    let os = "Linux";
    if (ua.includes("Windows")) os = "Windows";
    else if (ua.includes("Macintosh") || ua.includes("Mac OS")) os = "macOS";
    else if (ua.includes("Android")) os = "Android";

    return {
        clientId,
        clientName,
        os,
        browser,
        platform: navigator.platform || os,
        extensionVersion: chrome.runtime.getManifest().version
    };
}

// ─── Central Server Registration & Heartbeat ────────────────────────────────
async function registerClient() {
    await initServerConfig();
    const info = getSystemInfo();
    try {
        const res = await fetchWithTimeout(
            `${BACKEND_URL}/api/clients/register`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(info),
            },
            7000
        );
        if (res.ok) {
            const data = await res.json();
            isRegistered = true;
            if (data.rules) syncRules(data.rules);
            console.log("PhishGuard enrolled with central server:", clientId);
        }
    } catch (err) {
        console.warn("Central server registration deferred (server offline or unreachable):", err.message);
    }
}

async function sendHeartbeat() {
    if (!clientId) await initServerConfig();
    if (!isRegistered) {
        await registerClient();
    }
    try {
        let total = 0, phishing = 0, suspicious = 0, safe = 0;
        tabStats.forEach(s => {
            total += s.total || 0;
            phishing += s.phishing || 0;
            suspicious += s.suspicious || 0;
            safe += s.safe || 0;
        });

        const res = await fetchWithTimeout(
            `${BACKEND_URL}/api/clients/heartbeat`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    clientId,
                    clientName,
                    stats: { total, phishing, suspicious, safe },
                    extensionVersion: chrome.runtime.getManifest().version
                }),
            },
            5000
        );

        if (res.ok) {
            isRegistered = true;
            const data = await res.json();
            if (data.rules) syncRules(data.rules);
            // The server just answered, so it is reachable right now: this
            // is the natural moment to drain anything queued while it was
            // down. Automatic — the user never triggers a sync by hand.
            flushUrlEventQueue();
        }
    } catch { /* Silent on network heartbeat miss */ }
}

function syncRules(rules) {
    if (rules.whitelist && Array.isArray(rules.whitelist)) {
        serverWhitelistRules = new Set(rules.whitelist.map(r => (typeof r === "string" ? r : r.pattern).toLowerCase()));
    }
    if (rules.phishing && Array.isArray(rules.phishing)) {
        serverPhishingRules = new Set(rules.phishing.map(r => (typeof r === "string" ? r : r.pattern).toLowerCase()));
    }
    // Persist the last-known-good rule sets to disk so the extension keeps
    // enforcing them even if the service worker restarts before the next
    // successful sync (e.g. Chrome restart while the server is unreachable).
    chrome.storage.local.set({
        pgLastRulesSync: Date.now(),
        pgCachedWhitelist: Array.from(serverWhitelistRules),
        pgCachedPhishing: Array.from(serverPhishingRules)
    }).catch(() => {});
}

// Load the last cached rule sets from disk immediately on service-worker
// startup, so protection is active even before the first network round trip
// completes (covers Chrome restart / cold start on any machine).
async function loadCachedRules() {
    try {
        const { pgCachedWhitelist, pgCachedPhishing } = await chrome.storage.local.get(["pgCachedWhitelist", "pgCachedPhishing"]);
        if (Array.isArray(pgCachedWhitelist)) serverWhitelistRules = new Set(pgCachedWhitelist);
        if (Array.isArray(pgCachedPhishing)) serverPhishingRules = new Set(pgCachedPhishing);
    } catch { }
}

// Explicit, on-demand rule sync — used by the "Update Rules" button in the
// popup and by the periodic alarm below. Independent of registration and
// heartbeat so a stale/unregistered client can still force a fresh pull of
// the administrator whitelist + phishing rules from the central server.
async function fetchRulesNow() {
    if (!clientId) await initServerConfig();
    try {
        const res = await fetchWithTimeout(`${BACKEND_URL}/api/rules`, { method: "GET" }, 8000);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const rules = await res.json();
        syncRules(rules);
        return { ok: true, whitelistCount: serverWhitelistRules.size, phishingCount: serverPhishingRules.size };
    } catch (err) {
        return { ok: false, error: err?.message || "Rule sync failed (server unreachable)" };
    }
}

// ─── Durable URL-event telemetry queue ──────────────────────────────────────
//
// WHY THIS EXISTS
//
// scanUrl() resolves many verdicts locally and returns immediately — an
// administrator phishing-rule match, an administrator whitelist match, a
// known-safe apex domain, a user-trusted domain, and any repeat visit
// inside the 15-minute verdict cache. Every one of those paths used to
// return WITHOUT contacting the server, so the visit was never recorded in
// URL History at all. The user really did browse there, so it belongs in
// the history.
//
// That is what produced every symptom in the bug report:
//   - "some URLs appear, some don't"  -> whitelisted / safe-apex / rule-
//     matched navigations were silently never sent;
//   - "the number changes after a while" -> as the 15-minute verdict cache
//     warms up, MORE revisits get short-circuited, so the same browsing
//     session yields fewer recorded events over time;
//   - "blocked phishing URLs are missing from history" -> a rule match
//     raised a Threat Alert but never wrote a URL event.
//
// So: the local fast path is kept exactly as-is (it is what makes blocking
// instant and keeps the extension working offline), but the observation is
// now ALWAYS queued for the server, on every path, without exception.
//
// The queue is persisted in chrome.storage.local, so it survives service-
// worker suspension, browser restart, and server downtime. Each entry
// carries a stable eventId minted once at observation time and reused on
// every retry, which is what lets the server dedupe replays instead of
// accumulating duplicate rows.

const QUEUE_KEY = "pgUrlEventQueue";
const QUEUE_MAX = 5000;          // hard safety ceiling on unsent backlog
const FLUSH_BATCH_SIZE = 200;
let flushInProgress = false;

function newEventId() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
    return `evt-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
}

// `eventId` is supplied by the caller so that ONE observed navigation keeps
// ONE identity no matter which path reports it. In particular, if a live
// /api/scan request is sent and its response is lost to a dropped
// connection, the very same eventId is queued for replay — and because the
// server already stored that id, the replay is recognised as a duplicate
// instead of becoming a second history row for a single visit.
async function enqueueUrlEvent(url, source, eventId) {
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;
    try {
        if (!clientId) await initServerConfig();
        const { [QUEUE_KEY]: queue = [] } = await chrome.storage.local.get(QUEUE_KEY);
        queue.push({
            eventId: eventId || newEventId(),
            url,
            source: source || "extension-navigation",
            observedAt: new Date().toISOString()
        });
        // Drop the OLDEST entries if the backlog is somehow unbounded
        // (server down for a very long time). Newest observations are the
        // ones most likely to still matter.
        const trimmed = queue.length > QUEUE_MAX ? queue.slice(queue.length - QUEUE_MAX) : queue;
        await chrome.storage.local.set({ [QUEUE_KEY]: trimmed });
    } catch (e) {
        console.warn("PhishGuard: could not queue URL event:", e?.message);
        return;
    }
    // Opportunistic immediate flush; if the server is unreachable the entry
    // simply stays queued and the alarm below retries it later.
    flushUrlEventQueue();
}

async function flushUrlEventQueue() {
    if (flushInProgress) return { ok: false, reason: "flush already running" };
    flushInProgress = true;
    try {
        if (!clientId) await initServerConfig();

        // Loop so a large backlog (e.g. after extended downtime) drains
        // fully rather than one batch per alarm tick.
        for (;;) {
            const { [QUEUE_KEY]: queue = [] } = await chrome.storage.local.get(QUEUE_KEY);
            if (queue.length === 0) return { ok: true, flushed: 0 };

            const batch = queue.slice(0, FLUSH_BATCH_SIZE);
            const res = await fetchWithTimeout(
                `${BACKEND_URL}/api/url-events`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ clientId, clientName, events: batch })
                },
                15000
            );
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            // Remove ONLY the ids the server confirmed it has durably stored
            // (newly accepted plus already-present duplicates). Anything
            // unconfirmed stays queued and is retried. Re-read the queue
            // here rather than reusing the snapshot above, so events
            // enqueued during the round trip are not lost.
            const acked = new Set(data.acknowledgedIds || []);
            const { [QUEUE_KEY]: current = [] } = await chrome.storage.local.get(QUEUE_KEY);
            const remaining = current.filter(e => !acked.has(e.eventId));
            await chrome.storage.local.set({ [QUEUE_KEY]: remaining });

            if (acked.size === 0) return { ok: false, reason: "server acknowledged nothing" };
            if (remaining.length === 0) return { ok: true, flushed: acked.size };
        }
    } catch (err) {
        // Offline / server restarting: keep everything queued and retry.
        return { ok: false, error: err?.message || "flush failed" };
    } finally {
        flushInProgress = false;
    }
}

// ─── Rule match check ────────────────────────────────────────────────────────
function matchesRuleSet(url, ruleSet) {
    try {
        const host = new URL(url).hostname.toLowerCase();
        for (const pattern of ruleSet) {
            if (host === pattern || host.endsWith("." + pattern) || url.toLowerCase().includes(pattern)) {
                return pattern;
            }
        }
    } catch { }
    return null;
}

// ─── Cache & Persistence ────────────────────────────────────────────────────
async function addToRecentScans(url, verdict, score) {
    try {
        const { recentScans = [] } = await chrome.storage.local.get("recentScans");
        const entry = { url, verdict, score: score ?? 0, time: Date.now() };
        const updated = [entry, ...recentScans.filter(r => r.url !== url)].slice(0, 10);
        await chrome.storage.local.set({ recentScans: updated });
    } catch { }
}

async function getTrustedDomains() {
    const { trustedDomains } = await chrome.storage.local.get("trustedDomains");
    return trustedDomains || [];
}

async function isTrusted(url) {
    try {
        const host = new URL(url).hostname;
        const trusted = await getTrustedDomains();
        return trusted.some(d => host === d || host.endsWith("." + d));
    } catch {
        return false;
    }
}

// ─── Real URL Scanning & Telemetry Relay ───────────────────────────────────
async function scanUrl(url, source = "extension-navigation") {
    // ONE observation == ONE eventId, minted here, before any branch is
    // taken. Whichever path below resolves the verdict, this same id is what
    // reaches the server, so the observation is recorded exactly once.
    const eventId = newEventId();

    // 1. Check Server Phishing Rules
    const matchedPhish = matchesRuleSet(url, serverPhishingRules);
    if (matchedPhish) {
        const result = {
            verdict: "PHISHING",
            score: 0.99,
            reasons: [`Blocked by Administrator Phishing Rule: "${matchedPhish}"`],
            ruleMatch: true
        };
        verdictCache.set(url, { time: Date.now(), data: result });
        addToRecentScans(url, "PHISHING", 0.99);
        reportThreatAlert(url, 0.99, result.reasons, source);
        // A blocked navigation is still a navigation: record it in history
        // too, not only in Threat Alerts.
        enqueueUrlEvent(url, source, eventId);
        return result;
    }

    // 2. Check Server Whitelist Rules
    const matchedWhite = matchesRuleSet(url, serverWhitelistRules);
    if (matchedWhite) {
        enqueueUrlEvent(url, source, eventId);
        return {
            verdict: "SAFE",
            score: 0,
            whitelisted: true,
            reasons: [`Allowed by Administrator Whitelist Rule: "${matchedWhite}"`]
        };
    }

    // 3. Check Safe Apex & Local Trust
    if (SAFE_APEX.has(apexDomain(url))) {
        enqueueUrlEvent(url, source, eventId);
        return { verdict: "SAFE", score: 0, whitelisted: true, reasons: ["Domain is in standard safe directory"] };
    }
    if (await isTrusted(url)) {
        enqueueUrlEvent(url, source, eventId);
        return { verdict: "SAFE", score: 0, trusted: true, reasons: ["Domain is in user trusted list"] };
    }

    // 4. Check cache
    //
    // The cache exists to avoid re-querying the server for a VERDICT that is
    // still fresh. It must not suppress the HISTORY record: a revisit is a
    // separate navigation and gets its own event.
    const cached = verdictCache.get(url);
    if (cached && Date.now() - cached.time < CACHE_TTL_MS) {
        enqueueUrlEvent(url, source, eventId);
        return cached.data;
    }
    if (inFlight.has(url)) {
        // A concurrent scan of the same URL is already running. Share its
        // verdict, but still record this navigation as its own event.
        enqueueUrlEvent(url, source, eventId);
        return inFlight.get(url);
    }

    // 5. Query Central Server
    const promise = (async () => {
        try {
            const res = await fetchWithTimeout(
                `${BACKEND_URL}/api/scan`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    // eventId makes this write idempotent server-side.
                    body: JSON.stringify({ url, source, clientId, clientName, eventId }),
                },
                FETCH_TIMEOUT_MS
            );
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            verdictCache.set(url, { time: Date.now(), data });
            if (data.verdict && data.verdict !== "ERROR") {
                addToRecentScans(url, data.verdict, data.score ?? 0);
            }
            return data;
        } catch (err) {
            console.warn("PhishGuard scan relay error:", err.message);
            // The server did not confirm the write, so queue this
            // observation for replay under the SAME eventId. If the request
            // actually did land and only the response was lost, the replay
            // is deduped server-side rather than double-counted.
            enqueueUrlEvent(url, source, eventId);
            // Fallback safe offline heuristic
            return { verdict: "SAFE", score: 0.1, offline: true, reasons: ["Detection server unreachable; offline heuristic passed"] };
        } finally {
            inFlight.delete(url);
        }
    })();

    inFlight.set(url, promise);
    return promise;
}

async function bulkScanUrls(urls, source = "extension-link") {
    const resultMap = new Map();
    const toFetch   = [];

    for (const url of urls) {
        const matchedPhish = matchesRuleSet(url, serverPhishingRules);
        if (matchedPhish) {
            resultMap.set(url, { verdict: "PHISHING", score: 0.99, reasons: ["Policy Phishing Rule"] });
            continue;
        }
        const matchedWhite = matchesRuleSet(url, serverWhitelistRules);
        if (matchedWhite) {
            resultMap.set(url, { verdict: "SAFE", score: 0, whitelisted: true });
            continue;
        }
        if (SAFE_APEX.has(apexDomain(url)) || (await isTrusted(url))) {
            resultMap.set(url, { verdict: "SAFE", score: 0 });
            continue;
        }
        const cached = verdictCache.get(url);
        if (cached && Date.now() - cached.time < CACHE_TTL_MS) {
            resultMap.set(url, cached.data);
        } else {
            toFetch.push(url);
        }
    }

    if (toFetch.length > 0) {
        // One id per URL, minted before the request, so a failed/lost
        // response can be replayed under the same ids without duplicating.
        const eventIds = toFetch.map(() => newEventId());
        try {
            const res = await fetchWithTimeout(
                `${BACKEND_URL}/api/bulk-scan`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ urls: toFetch, eventIds, source, clientId, clientName }),
                },
                BULK_TIMEOUT_MS
            );
            if (res.ok) {
                const data = await res.json();
                (data.results || []).forEach((r, i) => {
                    const u = toFetch[i];
                    verdictCache.set(u, { time: Date.now(), data: r });
                    resultMap.set(u, r);
                });
            }
        } catch (err) {
            // Server unreachable. These links would have been recorded had
            // the request succeeded, so queue them for automatic replay
            // instead of dropping the telemetry on the floor.
            toFetch.forEach((u, i) => {
                resultMap.set(u, { verdict: "SAFE", score: 0.1, offline: true });
                enqueueUrlEvent(u, source, eventIds[i]);
            });
        }
    }

    return urls.map(u => resultMap.get(u) || { verdict: "SAFE", score: 0.1 });
}

// ─── Real Threat Notification & Alert Relay ────────────────────────────────
// Fires the native OS notification (Windows toast / macOS banner / Linux
// notification) directly from THIS machine's extension — never relayed
// through the server, so it works identically on localhost and on every
// remote installation, independent of the central server's own OS.
function triggerPhishingAlarm(url, score, reasons) {
    if (!chrome.notifications) {
        console.warn("PhishGuard: chrome.notifications API unavailable in this browser context");
        return;
    }
    let domain = url;
    try { domain = new URL(url).hostname; } catch { }

    const notificationId = `pg-threat-${Date.now()}`;
    try {
        chrome.notifications.create(
            notificationId,
            {
                type: "basic",
                iconUrl: chrome.runtime.getURL("icon.png"),
                title: "🛑 PhishGuard: Threat Intercepted",
                message: `Blocked phishing destination: ${domain} (Risk: ${(score * 100).toFixed(0)}%)`,
                priority: 2,
                requireInteraction: true
            },
            (createdId) => {
                if (chrome.runtime.lastError) {
                    // Surface the exact reason a Windows/OS popup failed to
                    // appear on this machine (e.g. OS notification permission
                    // revoked for Chrome) instead of failing silently.
                    console.error("PhishGuard: notification create failed:", chrome.runtime.lastError.message);
                } else {
                    // Auto-clear after 20s so alerts don't pile up in the
                    // Windows Action Center indefinitely.
                    setTimeout(() => chrome.notifications.clear(createdId).catch(() => {}), 20000);
                }
            }
        );
    } catch (e) {
        console.error("PhishGuard: notification create threw:", e);
    }
}

// Verify the OS-level notification permission on startup so failures are
// diagnosable per-machine instead of appearing as a generic "doesn't work
// on remote PCs" report.
chrome.notifications?.getPermissionLevel?.((level) => {
    if (level !== "granted") {
        console.warn(`PhishGuard: OS notification permission is "${level}" on this machine — Windows/OS popups will not appear until the user allows notifications for Chrome in OS settings.`);
    }
});

async function reportThreatAlert(url, score, reasons, source = "extension-blocking") {
    let domain = url;
    try { domain = new URL(url).hostname; } catch { }
    triggerPhishingAlarm(url, score, reasons);

    try {
        await fetchWithTimeout(
            `${BACKEND_URL}/api/threats/alert`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    clientId,
                    clientName,
                    url,
                    domain,
                    score,
                    reasons,
                    source
                }),
            },
            5000
        );
    } catch { }
}

// ─── Navigation Interception & Blocking ─────────────────────────────────────
function redirectToWarning(tabId, url, data, verdict = "PHISHING") {
    reportThreatAlert(url, data.score ?? data.risk_score ?? 0.9, data.reasons || [], "navigation-block");

    const warningUrl =
        chrome.runtime.getURL("warning.html") +
        `?url=${encodeURIComponent(url)}` +
        `&score=${encodeURIComponent(data.score ?? data.risk_score ?? 0)}` +
        `&reasons=${encodeURIComponent(JSON.stringify(data.reasons || []))}` +
        `&verdict=${encodeURIComponent(verdict)}`;
    chrome.tabs.update(tabId, { url: warningUrl }).catch(() => {});
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    if (bypassedUrls.has(url)) {
        bypassedUrls.delete(url);
        return;
    }

    const cached = verdictCache.get(url);
    if (cached && Date.now() - cached.time < CACHE_TTL_MS) {
        if (cached.data.verdict === "PHISHING") redirectToWarning(details.tabId, url, cached.data);
        else if (cached.data.verdict === "SUSPICIOUS") redirectToWarning(details.tabId, url, cached.data, "SUSPICIOUS");
        chrome.storage.local.set({ [`tabScan_${details.tabId}`]: { url, data: cached.data, time: cached.time } }).catch(() => {});
        return;
    }

    const tabId = details.tabId;
    scanUrl(url, "extension-navigation").then(data => {
        if (!data || data.verdict === "ERROR") return;
        if (data.verdict === "PHISHING") redirectToWarning(tabId, url, data);
        else if (data.verdict === "SUSPICIOUS") redirectToWarning(tabId, url, data, "SUSPICIOUS");
        chrome.storage.local.set({ [`tabScan_${tabId}`]: { url, data, time: Date.now() } }).catch(() => {});
    }).catch(() => {});
});

// ─── Badge Management ───────────────────────────────────────────────────────
function updateBadge(tabId, stats) {
    if (!stats || (stats.phishing === 0 && stats.suspicious === 0)) {
        chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
        return;
    }
    if (stats.phishing > 0) {
        chrome.action.setBadgeText({ text: String(stats.phishing), tabId }).catch(() => {});
        chrome.action.setBadgeBackgroundColor({ color: "#dc3545", tabId }).catch(() => {});
    } else {
        chrome.action.setBadgeText({ text: String(stats.suspicious), tabId }).catch(() => {});
        chrome.action.setBadgeBackgroundColor({ color: "#ffc107", tabId }).catch(() => {});
    }
}

// ─── Message Handling ───────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "scan") {
        scanUrl(message.url, message.source || "extension-popup").then(sendResponse);
        return true;
    }

    if (message.action === "bulkScan") {
        bulkScanUrls(message.urls, message.source || "extension-link").then(results => {
            sendResponse({ results });
        });
        return true;
    }

    if (message.action === "reportBlockedClick") {
        reportThreatAlert(message.url, message.score || 0.8, ["In-page phishing link click blocked"], "in-page-click");
        sendResponse({ ok: true });
        return false;
    }

    if (message.action === "updateRulesNow") {
        fetchRulesNow().then(sendResponse);
        return true;
    }

    if (message.action === "getQueueStatus") {
        chrome.storage.local.get(QUEUE_KEY).then(r => {
            sendResponse({ pending: (r[QUEUE_KEY] || []).length });
        }).catch(() => sendResponse({ pending: 0 }));
        return true;
    }

    if (message.action === "flushQueueNow") {
        flushUrlEventQueue().then(sendResponse);
        return true;
    }

    if (message.action === "getCached") {
        const c = verdictCache.get(message.url);
        sendResponse(c ? c.data : null);
        return false;
    }

    if (message.action === "updateStats") {
        const tabId = sender.tab?.id;
        if (tabId != null) {
            tabStats.set(tabId, message.stats);
            updateBadge(tabId, message.stats);
        }
        sendResponse({ ok: true });
        return false;
    }

    if (message.action === "getStats") {
        sendResponse(tabStats.get(message.tabId) || { total: 0, phishing: 0, suspicious: 0, safe: 0 });
        return false;
    }

    if (message.action === "trustDomain") {
        chrome.storage.local.get("trustedDomains", ({ trustedDomains }) => {
            const domains = trustedDomains || [];
            if (!domains.includes(message.domain)) domains.push(message.domain);
            chrome.storage.local.set({ trustedDomains: domains }, () => sendResponse({ ok: true }));
        });
        return true;
    }

    if (message.action === "untrustDomain") {
        chrome.storage.local.get("trustedDomains", ({ trustedDomains }) => {
            const domains = (trustedDomains || []).filter(d => d !== message.domain);
            chrome.storage.local.set({ trustedDomains: domains }, () => sendResponse({ ok: true }));
        });
        return true;
    }

    if (message.action === "getTrustedDomains") {
        getTrustedDomains().then(sendResponse);
        return true;
    }

    if (message.action === "getRecentScans") {
        chrome.storage.local.get("recentScans", ({ recentScans }) => {
            sendResponse(recentScans || []);
        });
        return true;
    }

    if (message.action === "bypassUrl") {
        bypassedUrls.add(message.url);
        sendResponse({ ok: true });
        return false;
    }

    if (message.action === "reconnectServer") {
        if (message.serverUrl) {
            BACKEND_URL = message.serverUrl.trim().replace(/\/$/, "");
        }
        initServerConfig().then(() => {
            isRegistered = false;
            registerClient().then(sendHeartbeat).then(flushUrlEventQueue);
            sendResponse({ ok: true, serverUrl: BACKEND_URL });
        });
        return true;
    }
});

// ─── Alarms & Recurring Heartbeat / Rule Sync ───────────────────────────────
// chrome.alarms (unlike setInterval) survives Manifest V3 service-worker
// suspension, so this is what guarantees rules keep syncing automatically
// even if the worker has been unloaded between events.
chrome.alarms.create("pg_heartbeat", { periodInMinutes: 0.5 });
chrome.alarms.create("pg_rule_sync", { periodInMinutes: 2 });
// Retry timer for unsent URL telemetry. Uses chrome.alarms rather than
// setInterval so it keeps firing after the MV3 service worker is suspended
// and revived — that is what guarantees a queue built up while the server
// was down is delivered automatically, with no user action.
chrome.alarms.create("pg_event_flush", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "pg_heartbeat") {
        sendHeartbeat();
    } else if (alarm.name === "pg_rule_sync") {
        fetchRulesNow();
    } else if (alarm.name === "pg_event_flush") {
        flushUrlEventQueue();
    }
});

setInterval(sendHeartbeat, HEARTBEAT_INTERVAL_MS);

// ─── Startup & Installation Lifecycle ──────────────────────────────────────
chrome.runtime.onStartup.addListener(() => {
    loadCachedRules().then(() => initServerConfig()).then(() => {
        registerClient().then(sendHeartbeat);
        fetchRulesNow();
        // Deliver anything queued before the browser was closed.
        flushUrlEventQueue();
    });
});

// ─── Context Menus ──────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
    registerClient().then(fetchRulesNow);
    try {
        chrome.contextMenus.create({
            id: "phishguard-scan-link",
            title: "🛡 Scan this link with PhishGuard SOC",
            contexts: ["link"],
        });
        chrome.contextMenus.create({
            id: "phishguard-scan-page",
            title: "🛡 Scan this page with PhishGuard SOC",
            contexts: ["page"],
        });
    } catch { }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    const url = info.menuItemId === "phishguard-scan-link" ? info.linkUrl : info.pageUrl;
    if (!url || !tab?.id) return;
    scanUrl(url, "context-menu").then(data => {
        chrome.tabs.sendMessage(tab.id, { action: "showScanToast", url, data }).catch(() => {});
    }).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
    tabStats.delete(tabId);
    chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
    chrome.storage.local.remove(`tabScan_${tabId}`).catch(() => {});
});

// ─── Initialization ─────────────────────────────────────────────────────────
loadCachedRules().then(() => initServerConfig()).then(() => {
    registerClient();
    sendHeartbeat();
    fetchRulesNow();
    // Cold start / service-worker revival: drain any queue left on disk.
    flushUrlEventQueue();
});
console.log("PhishGuard Enterprise Agent service worker active");
