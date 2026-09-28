// PhishGuard warning page script
const params      = new URLSearchParams(window.location.search);
const blockedUrl  = params.get("url") || "";
const score       = parseFloat(params.get("score") || "0");
const verdict     = (params.get("verdict") || "PHISHING").toUpperCase();
const isSuspicious = verdict === "SUSPICIOUS";

let reasons = [];
try { reasons = JSON.parse(decodeURIComponent(params.get("reasons") || "[]")); }
catch { reasons = []; }

if (isSuspicious) {
    document.body.classList.add("suspicious");
    document.title = "PhishGuard — Suspicious Site Warning";
    document.querySelector(".icon").textContent = "⚠️";
    document.querySelector("h1").textContent = "Suspicious Site Warning";
    document.querySelector(".subtitle").textContent =
        "PhishGuard flagged this website as suspicious. It hasn't been " +
        "confirmed malicious, but shows risk signals worth pausing on before you continue.";
}

document.getElementById("blockedUrl").textContent = blockedUrl || "(URL unavailable)";
document.getElementById("scorePill").textContent  = `Risk Score: ${(score * 100).toFixed(1)}%`;

if (Array.isArray(reasons) && reasons.length > 0) {
    document.getElementById("reasonsBlock").style.display = "block";
    const ul = document.getElementById("reasonsList");
    reasons.forEach(r => {
        const li = document.createElement("li");
        li.textContent = String(r);
        ul.appendChild(li);
    });
}

async function playWarningSound() {
    try {
        const data = await chrome.storage.local.get("pgSoundEnabled");
        if (data.pgSoundEnabled === false) return;
    } catch { return; }
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        function beep(freq, start, dur) {
            const osc  = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain); gain.connect(ctx.destination);
            osc.frequency.value = freq;
            gain.gain.setValueAtTime(0.4, start);
            gain.gain.exponentialRampToValueAtTime(0.001, start + dur);
            osc.start(start); osc.stop(start + dur + 0.05);
        }
        const t = ctx.currentTime;
        beep(880, t, 0.13); beep(660, t + 0.18, 0.13); beep(440, t + 0.36, 0.25);
    } catch { /* silent fail */ }
}

document.addEventListener("click", playWarningSound, { once: true, capture: true });

function goBack() {
    if (history.length > 1) history.back();
    else window.location.href = "https://www.google.com";
}

function proceedAnyway() {
    if (!blockedUrl) return;
    const confirmMsg = isSuspicious
        ? "⚠️ Caution\n\nThis site shows suspicious characteristics but has not been confirmed malicious.\n\nProceed anyway?"
        : "⚠️ Warning\n\nThis site is very likely to steal your credentials or install malware.\n\nAre you absolutely sure you want to proceed?";
    const confirmed = confirm(confirmMsg);
    if (!confirmed) return;
    chrome.runtime.sendMessage({ action: "bypassUrl", url: blockedUrl }, () => {
        window.location.href = blockedUrl;
    });
}

document.getElementById("btnBack").addEventListener("click", goBack);
document.getElementById("btnProceed").addEventListener("click", proceedAnyway);
