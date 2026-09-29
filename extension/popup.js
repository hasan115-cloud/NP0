// PhishGuard Popup v1.4

let currentTabUrl  = "";
let currentDomain  = "";
let isTrusted      = false;
let currentServer  = (typeof PHISHGUARD_DEFAULT_CONFIG !== "undefined" && PHISHGUARD_DEFAULT_CONFIG.SERVER_URL)
    ? PHISHGUARD_DEFAULT_CONFIG.SERVER_URL.trim().replace(/\/$/, "")
    : "";

function shorten(url, n = 45) {
    return url.length > n ? url.substring(0, n) + "…" : url;
}

function safeHost(url) {
    try { return new URL(url).hostname; } catch { return url; }
}

async function getServerUrl() {
    const { phishguardServerUrl } = await chrome.storage.local.get("phishguardServerUrl");
    if (phishguardServerUrl && phishguardServerUrl.trim()) {
        currentServer = phishguardServerUrl.trim().replace(/\/$/, "");
    } else if (typeof PHISHGUARD_DEFAULT_CONFIG !== "undefined" && PHISHGUARD_DEFAULT_CONFIG.SERVER_URL) {
        currentServer = PHISHGUARD_DEFAULT_CONFIG.SERVER_URL.trim().replace(/\/$/, "");
    }
    return currentServer;
}

async function updateServerStatusUI() {
    const srv = await getServerUrl();
    const dot = document.getElementById("serverStatusDot");
    const txt = document.getElementById("serverStatusText");
    const input = document.getElementById("serverUrlInput");
    if (input) input.value = srv;

    const { phishguardClientId } = await chrome.storage.local.get("phishguardClientId");
    const cidEl = document.getElementById("displayClientId");
    if (cidEl && phishguardClientId) cidEl.textContent = phishguardClientId;

    try {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 2500);
        const res = await fetch(`${srv}/api/health`, { signal: controller.signal });
        clearTimeout(t);
        if (res.ok) {
            dot.className = "status-dot online";
            txt.textContent = "Online";
            txt.style.color = "#4ade80";
        } else {
            dot.className = "status-dot offline";
            txt.textContent = "Offline";
            txt.style.color = "#ff6b7a";
        }
    } catch {
        dot.className = "status-dot offline";
        txt.textContent = "Unreachable";
        txt.style.color = "#ff6b7a";
    }
}

function renderResult(data) {
    const area        = document.getElementById("verdictArea");
    const reasonsArea = document.getElementById("reasonsArea");
    const reasonsList = document.getElementById("reasonsList");

    if (!data || !data.verdict || data.verdict === "ERROR") {
        area.className = "verdict-card vc-loading";
        area.innerHTML = `
            <div style="color:#ff6b7a;font-size:0.9rem;font-weight:600;">Scan Inconclusive</div>
            <div style="font-size:0.72rem;color:#9aabc4;margin-top:5px;">Unable to reach detection backend or network timeout. Check Central Server configuration.</div>`;
        reasonsArea.style.display = "none";
        return;
    }

    if (data.trusted) {
        area.className = "verdict-card vc-safe";
        area.innerHTML = `
            <div class="verdict-icon verdict-safe">✓</div>
            <div class="verdict-label verdict-safe">Trusted Domain</div>
            <div class="verdict-score">Matched administrator whitelist or local trusted list.</div>`;
        reasonsArea.style.display = "none";
        return;
    }

    const verdict = data.verdict;
    const score   = data.score ?? data.risk_score ?? 0;
    const percent = (score * 100).toFixed(1);

    const MAP = {
        PHISHING:   { icon: "🛑", label: "Phishing Site Blocked", color: "verdict-phishing",  bg: "vc-phishing"  },
        SUSPICIOUS: { icon: "⚠️", label: "Suspicious Warning",    color: "verdict-suspicious", bg: "vc-suspicious" },
        SAFE:       { icon: "✅", label: "Safe Domain",           color: "verdict-safe",       bg: "vc-safe"       },
    };
    const cfg = MAP[verdict] || MAP.SAFE;

    area.className = `verdict-card ${cfg.bg}`;
    area.innerHTML = `
        <div class="verdict-icon ${cfg.color}">${cfg.icon}</div>
        <div class="verdict-label ${cfg.color}">${cfg.label}</div>
        <div class="verdict-score">Risk Probability: ${percent}%</div>
        <a href="#" id="dashboardLink" style="font-size:0.68rem;color:#ffffff;text-decoration:none;display:inline-block;margin-top:6px;">Open Dashboard →</a>`;

    document.getElementById("dashboardLink")?.addEventListener("click", (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: currentServer });
    });

    const reasons = data.reasons || [];
    if (reasons.length > 0) {
        reasonsArea.style.display = "block";
        reasonsList.innerHTML = "";
        reasons.slice(0, 4).forEach(r => {
            const div = document.createElement("div");
            div.className = "reason-item";
            div.textContent = String(r);
            reasonsList.appendChild(div);
        });
    } else {
        reasonsArea.style.display = "none";
    }
}

function loadPageStats(tabId) {
    chrome.runtime.sendMessage({ action: "getStats", tabId }, (stats) => {
        if (!stats || stats.total === 0) return;
        const bar = document.getElementById("statsBar");
        bar.style.display = "flex";
        document.getElementById("statTotal").textContent      = `${stats.total} scanned`;
        document.getElementById("statPhishing").textContent   = `${stats.phishing} phishing`;
        document.getElementById("statSuspicious").textContent = `${stats.suspicious} suspicious`;
        document.getElementById("statSafe").textContent       = `${stats.safe} safe`;
    });
}

function renderTrustRow() {
    const row = document.getElementById("trustRow");
    if (!currentDomain) { row.style.display = "none"; return; }
    row.style.display = "flex";

    const btn     = document.getElementById("trustBtn");
    const unbtn   = document.getElementById("untrustBtn");
    const label   = document.getElementById("trustLabel");

    if (isTrusted) {
        label.textContent   = `${currentDomain} is trusted`;
        btn.textContent     = "✅ Trusted";
        btn.className       = "btn-trust trusted";
        unbtn.style.display = "inline";
    } else {
        label.textContent   = `Trust ${currentDomain}?`;
        btn.textContent     = "+ Trust";
        btn.className       = "btn-trust";
        unbtn.style.display = "none";
    }
}

function toggleTrust() {
    if (!currentDomain) return;
    if (isTrusted) {
        chrome.runtime.sendMessage({ action: "untrustDomain", domain: currentDomain }, () => {
            isTrusted = false;
            renderTrustRow();
        });
    } else {
        chrome.runtime.sendMessage({ action: "trustDomain", domain: currentDomain }, () => {
            isTrusted = true;
            renderTrustRow();
        });
    }
}

async function checkTrusted() {
    return new Promise(resolve => {
        chrome.runtime.sendMessage({ action: "getTrustedDomains" }, (domains) => {
            if (chrome.runtime.lastError) { resolve(false); return; }
            resolve((domains || []).includes(currentDomain));
        });
    });
}

function showLoading() {
    const area = document.getElementById("verdictArea");
    area.className = "verdict-card vc-loading";
    area.innerHTML = `
        <div class="spinner"></div>
        <div style="margin-top:6px;font-size:0.85rem;color:#9aabc4;">Scanning telemetry...</div>`;
    document.getElementById("reasonsArea").style.display  = "none";
    document.getElementById("statsBar").style.display     = "none";
}

async function scanCurrentTab(forceRescan = false) {
    showLoading();

    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab  = tabs[0];

    if (!tab || !tab.url || !tab.url.startsWith("http")) {
        renderResult({ verdict: "ERROR" });
        document.getElementById("currentUrl").textContent = "Non-web address (internal / chrome page)";
        return;
    }

    currentTabUrl = tab.url;
    currentDomain = safeHost(tab.url);
    document.getElementById("currentUrl").textContent = shorten(tab.url);

    isTrusted = await checkTrusted();
    renderTrustRow();

    if (isTrusted) {
        renderResult({ verdict: "SAFE", trusted: true });
        loadPageStats(tab.id);
        return;
    }

    if (!forceRescan) {
        const stored = await chrome.storage.local.get(`tabScan_${tab.id}`);
        const cached = stored[`tabScan_${tab.id}`];
        const CACHE_MAX = 15 * 60 * 1000;
        if (cached && cached.url === tab.url && (Date.now() - cached.time) < CACHE_MAX) {
            renderResult(cached.data);
            loadPageStats(tab.id);
            return;
        }
    }

    // Ask background service worker to scan and relay telemetry to central server
    chrome.runtime.sendMessage({
        action: "scan",
        url: tab.url,
        source: forceRescan ? "extension-popup-rescan" : "extension-popup"
    }, (data) => {
        if (chrome.runtime.lastError || !data) {
            renderResult({ verdict: "ERROR" });
        } else {
            renderResult(data);
            loadPageStats(tab.id);
        }
    });
}

let recentOpen = false;
function toggleRecent() {
    recentOpen = !recentOpen;
    document.getElementById("recentList").style.display = recentOpen ? "block" : "none";
    document.getElementById("recentChevron").textContent = recentOpen ? "▴" : "▾";
}

function loadRecentScans() {
    chrome.runtime.sendMessage({ action: "getRecentScans" }, (scans) => {
        if (!scans || scans.length === 0) return;
        const section = document.getElementById("recentSection");
        const list    = document.getElementById("recentList");
        section.style.display = "block";
        list.innerHTML = "";
        scans.forEach(s => {
            const cls = s.verdict === "PHISHING" ? "rv-phishing"
                      : s.verdict === "SUSPICIOUS" ? "rv-suspicious" : "rv-safe";
            const icon = s.verdict === "PHISHING" ? "⛔" : s.verdict === "SUSPICIOUS" ? "⚠️" : "✅";
            const item = document.createElement("div");
            item.className = "recent-item";
            item.title = s.url;
            const recentScore = (s.score ?? s.risk_score ?? 0) * 100;
            item.innerHTML = `
                <span class="recent-verdict ${cls}">${icon}</span>
                <span class="recent-url">${safeHost(s.url)}</span>
                <span class="${cls}" style="font-size:0.68rem;">${recentScore.toFixed(0)}%</span>`;
            item.addEventListener("click", () => {
                chrome.tabs.create({ url: s.url });
            });
            list.appendChild(item);
        });
    });
}

function toggleSettings() {
    const p = document.getElementById("settingsPanel");
    p.style.display = p.style.display === "none" ? "block" : "none";
}

async function updateRulesNow() {
    const btn = document.getElementById("updateRulesBtn");
    const msg = document.getElementById("rulesStatusMsg");
    btn.disabled = true;
    msg.style.color = "#9aabc4";
    msg.textContent = "Syncing...";
    chrome.runtime.sendMessage({ action: "updateRulesNow" }, (result) => {
        btn.disabled = false;
        if (chrome.runtime.lastError || !result || !result.ok) {
            msg.style.color = "#ff6b7a";
            msg.textContent = "Sync failed — server unreachable";
            return;
        }
        msg.style.color = "#4ade80";
        msg.textContent = `Synced: ${result.whitelistCount} whitelist, ${result.phishingCount} phishing rules`;
        setTimeout(() => { msg.textContent = ""; }, 5000);
    });
}

async function saveServerSettings() {
    const input = document.getElementById("serverUrlInput");
    let val = (input.value || "").trim().replace(/\/$/, "");
    if (!val) {
        val = (typeof PHISHGUARD_DEFAULT_CONFIG !== "undefined" && PHISHGUARD_DEFAULT_CONFIG.SERVER_URL)
            ? PHISHGUARD_DEFAULT_CONFIG.SERVER_URL.trim().replace(/\/$/, "")
            : currentServer;
    }
    if (!val) {
        const msg = document.getElementById("saveStatusMsg");
        msg.style.color = "#ff6b7a";
        msg.textContent = "Please enter server URL";
        setTimeout(() => { msg.textContent = ""; }, 3000);
        return;
    }
    if (!val.startsWith("http://") && !val.startsWith("https://")) {
        val = "https://" + val;
    }
    await chrome.storage.local.set({ phishguardServerUrl: val });
    currentServer = val;
    chrome.runtime.sendMessage({ action: "reconnectServer", serverUrl: val }).catch(() => {});
    const msg = document.getElementById("saveStatusMsg");
    msg.style.color = "#4ade80";
    msg.textContent = "Saved! Reconnecting...";
    setTimeout(() => { msg.textContent = ""; }, 3000);
    updateServerStatusUI();
}

async function getSoundEnabled() {
    const { pgSoundEnabled } = await chrome.storage.local.get("pgSoundEnabled");
    return pgSoundEnabled !== false;
}

async function toggleSound() {
    const current = await getSoundEnabled();
    const next = !current;
    await chrome.storage.local.set({ pgSoundEnabled: next });
    document.getElementById("soundBtn").textContent = next ? "🔔" : "🔕";
    document.getElementById("soundBtn").title = next ? "Sound ON (click to mute)" : "Sound OFF (click to enable)";
}

async function initSoundBtn() {
    const on = await getSoundEnabled();
    const btn = document.getElementById("soundBtn");
    btn.textContent = on ? "🔔" : "🔕";
    btn.title = on ? "Sound ON (click to mute)" : "Sound OFF (click to enable)";
}

document.getElementById("rescanBtn").addEventListener("click", () => scanCurrentTab(true));
document.getElementById("trustBtn").addEventListener("click", toggleTrust);
document.getElementById("untrustBtn").addEventListener("click", toggleTrust);
document.getElementById("recentToggleBtn").addEventListener("click", toggleRecent);
document.getElementById("soundBtn").addEventListener("click", toggleSound);
document.getElementById("settingsToggleBtn").addEventListener("click", toggleSettings);
document.getElementById("serverStatusPill").addEventListener("click", toggleSettings);
document.getElementById("saveServerBtn").addEventListener("click", saveServerSettings);
document.getElementById("updateRulesBtn").addEventListener("click", updateRulesNow);

scanCurrentTab();
loadRecentScans();
initSoundBtn();
updateServerStatusUI();
