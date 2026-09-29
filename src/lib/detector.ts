import { db } from "./db";
import { UrlClassification, UrlVerdict } from "./types";

const SAFE_DOMAINS = new Set([
  "google.com","bing.com","yahoo.com","duckduckgo.com","youtube.com",
  "microsoft.com","live.com","office.com","azure.com","outlook.com","github.com",
  "facebook.com","instagram.com","whatsapp.com","twitter.com","x.com",
  "linkedin.com","reddit.com","amazon.com","apple.com","icloud.com",
  "wikipedia.org","cloudflare.com","vercel.com","netlify.com"
]);

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "work", "click", "loan", "zip", "gq", "tk", "cf", "ml", "ga", "buzz", "rest", "surf"
]);

const SENSITIVE_KEYWORDS = [
  "login", "signin", "verify", "secure", "account", "banking", "update", "password",
  "credential", "wallet", "support", "auth", "confirm", "security", "recover"
];

const TARGET_BRANDS = [
  "paypal", "apple", "microsoft", "google", "netflix", "chase", "bankofamerica",
  "wellsfargo", "amazon", "facebook", "coinbase", "binance", "metamask", "steam"
];

export interface ScanResult {
  verdict: UrlClassification;
  action: UrlVerdict;
  score: number;
  domain: string;
  reasons: string[];
  whitelisted?: boolean;
  policyMatched?: boolean;
  ruleType?: "WHITELIST" | "PHISHING" | null;
}

export function matchesRulePattern(url: string, hostname: string, rawPattern: string): boolean {
  if (!rawPattern) return false;
  const p = rawPattern.trim().toLowerCase().replace(/^https?:\/\//, "");
  const h = hostname.toLowerCase().replace(/^www\./, "");
  const u = url.toLowerCase();

  // Pattern with wildcards on both ends, e.g. *keyword*
  if (p.startsWith("*") && p.endsWith("*") && p.length > 2) {
    const sub = p.slice(1, -1);
    return u.includes(sub) || h.includes(sub);
  }
  // Subdomain wildcard, e.g. *.google.com
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return h === base || h.endsWith("." + base);
  }
  // Suffix/TLD wildcard, e.g. *.zip
  if (p.startsWith("*")) {
    const suffix = p.slice(1);
    return h.endsWith(suffix) || u.endsWith(suffix);
  }
  // Prefix wildcard
  if (p.endsWith("*")) {
    const prefix = p.slice(0, -1);
    return h.startsWith(prefix) || u.includes(prefix);
  }
  // Exact domain, subdomain, or url substring match
  return h === p || h.endsWith("." + p) || u.includes(p);
}

export async function classifyUrl(targetUrl: string): Promise<ScanResult> {
  let urlObj: URL;
  try {
    urlObj = new URL(targetUrl);
  } catch {
    return {
      verdict: "SUSPICIOUS",
      action: "WARNING",
      score: 0.5,
      domain: targetUrl,
      reasons: ["Malformed or invalid URL format"]
    };
  }

  const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, "");
  const fullUrlLower = targetUrl.toLowerCase();
  const reasons: string[] = [];
  let riskScore = 0.05;

  // 1. Check Server Whitelist Rules
  const whitelist = await db.getWhitelistRules();
  for (const rule of whitelist) {
    if (matchesRulePattern(fullUrlLower, hostname, rule.pattern)) {
      return {
        verdict: "SAFE",
        action: "ALLOWED",
        score: 0.0,
        domain: hostname,
        reasons: [`Matched Administrator Whitelist Rule: "${rule.pattern}"`],
        whitelisted: true,
        ruleType: "WHITELIST"
      };
    }
  }

  // 2. Check Server Phishing Rules
  const phishingRules = await db.getPhishingRules();
  for (const rule of phishingRules) {
    if (matchesRulePattern(fullUrlLower, hostname, rule.pattern)) {
      return {
        verdict: "PHISHING",
        action: "BLOCKED",
        score: 0.99,
        domain: hostname,
        reasons: [`Enforced by Administrator Phishing Policy: "${rule.pattern}" — ${rule.reason}`],
        policyMatched: true,
        ruleType: "PHISHING"
      };
    }
  }

  // 3. Known Safe Apex Domains
  const parts = hostname.split(".");
  const apex = parts.slice(-2).join(".");
  if (SAFE_DOMAINS.has(hostname) || SAFE_DOMAINS.has(apex)) {
    return {
      verdict: "SAFE",
      action: "ALLOWED",
      score: 0.02,
      domain: hostname,
      reasons: ["Recognized verified major enterprise domain"]
    };
  }

  // 4. IP address in Hostname (High Risk)
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    riskScore += 0.65;
    reasons.push("Direct IP address host without domain registration");
  }

  // 5. Homoglyph / Punycode Attacks
  if (hostname.includes("xn--")) {
    riskScore += 0.55;
    reasons.push("Internationalized domain name (Punycode) detected (potential spoofing)");
  }

  // 6. Excessive Subdomains
  if (parts.length > 4) {
    riskScore += 0.35;
    reasons.push(`Unusually deep subdomain nesting (${parts.length} labels)`);
  }

  // 7. Suspicious TLD
  const tld = parts[parts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) {
    riskScore += 0.3;
    reasons.push(`High-abuse top-level domain (.${tld})`);
  }

  // 8. Brand Spoofing in Subdomain or Path
  let brandSpoofDetected = false;
  for (const brand of TARGET_BRANDS) {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.net`)) {
      riskScore += 0.55;
      brandSpoofDetected = true;
      reasons.push(`Brand targeting detected: "${brand}" in non-official domain`);
      break;
    }
  }

  // 9. Sensitive Security / Account Keywords
  let keywordCount = 0;
  for (const kw of SENSITIVE_KEYWORDS) {
    if (fullUrlLower.includes(kw)) {
      keywordCount++;
    }
  }
  if (keywordCount >= 2) {
    riskScore += 0.35;
    reasons.push(`Multiple deceptive security/credential terms detected (${keywordCount} keywords)`);
  } else if (keywordCount === 1 && brandSpoofDetected) {
    riskScore += 0.25;
    reasons.push("Combination of target brand name and authentication keyword");
  }

  // 10. URL Length and Path Entropy
  if (targetUrl.length > 90 && keywordCount > 0) {
    riskScore += 0.2;
    reasons.push("Abnormally long disguised URL string");
  }

  // Cap risk score between 0.01 and 0.99
  const finalScore = Math.min(0.99, Math.max(0.01, riskScore));

  let verdict: UrlClassification = "SAFE";
  let action: UrlVerdict = "ALLOWED";

  if (finalScore >= 0.65) {
    verdict = "PHISHING";
    action = "BLOCKED";
  } else if (finalScore >= 0.4) {
    verdict = "SUSPICIOUS";
    action = "WARNING";
  } else {
    verdict = "SAFE";
    action = "ALLOWED";
    if (reasons.length === 0) {
      reasons.push("Standard clean domain heuristics passed");
    }
  }

  return {
    verdict,
    action,
    score: parseFloat(finalScore.toFixed(2)),
    domain: hostname,
    reasons
  };
}
