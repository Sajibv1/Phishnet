// PhishGuard — fully offline heuristic phishing-link analyzer.
// No network calls are ever made; every check inspects URL structure only.

export type Verdict = "safe" | "low" | "suspicious" | "dangerous";
export type Severity = "critical" | "high" | "medium" | "low";
export type LogTone = "cmd" | "info" | "ok" | "warn" | "bad";

export interface RiskFactor {
  id: string;
  title: string;
  detail: string;
  severity: Severity;
  weight: number;
}

export interface PositiveSignal {
  title: string;
  detail: string;
}

export interface ScanResult {
  id: string;
  inputUrl: string;
  href: string;
  host: string;
  protocol: string;
  tld: string;
  riskScore: number;
  verdict: Verdict;
  factors: RiskFactor[];
  positives: PositiveSignal[];
  scannedAt: number;
}

export interface LogLine {
  text: string;
  tone: LogTone;
}

export interface ParsedTarget {
  url: URL;
  hadExplicitProtocol: boolean;
}

export const VERDICT_META: Record<Verdict, { label: string; blurb: string; color: string }> = {
  safe: {
    label: "CLEAN",
    blurb: "No meaningful phishing indicators found. Still inspect before entering credentials.",
    color: "#00ff9c",
  },
  low: {
    label: "LOW RISK",
    blurb: "A few weak signals surfaced. Probably fine — stay sharp.",
    color: "#ffd166",
  },
  suspicious: {
    label: "SUSPICIOUS",
    blurb: "Multiple red flags detected. This has the shape of a phishing lure.",
    color: "#ff9f43",
  },
  dangerous: {
    label: "DANGEROUS",
    blurb: "Classic phishing fingerprint. Do not open this link or enter any data.",
    color: "#ff4d6a",
  },
};

export const SEVERITY_STYLE: Record<Severity, { label: string; color: string }> = {
  critical: { label: "CRITICAL", color: "#ff4d6a" },
  high: { label: "HIGH", color: "#ff7849" },
  medium: { label: "MEDIUM", color: "#ffb454" },
  low: { label: "MINOR", color: "#ffd166" },
};

const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "club", "work",
  "click", "link", "icu", "cyou", "sbs", "monster", "quest", "zip", "mov", "rest",
]);

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
  "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "bit.do", "s.id",
]);

const KEYWORDS = [
  "login", "signin", "sign-in", "logon", "verify", "verification", "secure",
  "security", "account", "update", "confirm", "password", "passwd", "billing",
  "invoice", "payment", "wallet", "refund", "bonus", "prize", "winner", "gift",
  "claim", "urgent", "alert", "suspended", "locked", "unlock", "limited",
  "authenticate", "webscr", "recover", "restore", "kyc",
];

const BRANDS: Array<{ key: string; name: string; official: string[] }> = [
  { key: "paypal", name: "PayPal", official: ["paypal.com"] },
  { key: "apple", name: "Apple", official: ["apple.com"] },
  { key: "icloud", name: "iCloud", official: ["icloud.com"] },
  { key: "microsoft", name: "Microsoft", official: ["microsoft.com", "live.com", "msn.com"] },
  { key: "outlook", name: "Outlook", official: ["outlook.com", "live.com", "microsoft.com"] },
  { key: "gmail", name: "Gmail", official: ["gmail.com", "google.com"] },
  { key: "google", name: "Google", official: ["google.com", "youtube.com"] },
  { key: "youtube", name: "YouTube", official: ["youtube.com", "google.com"] },
  { key: "facebook", name: "Facebook", official: ["facebook.com", "fb.com"] },
  { key: "instagram", name: "Instagram", official: ["instagram.com"] },
  { key: "whatsapp", name: "WhatsApp", official: ["whatsapp.com"] },
  { key: "netflix", name: "Netflix", official: ["netflix.com"] },
  { key: "linkedin", name: "LinkedIn", official: ["linkedin.com"] },
  { key: "twitter", name: "Twitter / X", official: ["twitter.com", "x.com"] },
  { key: "coinbase", name: "Coinbase", official: ["coinbase.com"] },
  { key: "binance", name: "Binance", official: ["binance.com"] },
  { key: "metamask", name: "MetaMask", official: ["metamask.io"] },
  { key: "steampowered", name: "Steam", official: ["steampowered.com", "steamcommunity.com"] },
  { key: "dropbox", name: "Dropbox", official: ["dropbox.com"] },
  { key: "adobe", name: "Adobe", official: ["adobe.com"] },
  { key: "ebay", name: "eBay", official: ["ebay.com"] },
  { key: "amazon", name: "Amazon", official: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp"] },
  { key: "dhl", name: "DHL", official: ["dhl.com"] },
  { key: "fedex", name: "FedEx", official: ["fedex.com"] },
  { key: "usps", name: "USPS", official: ["usps.com"] },
  { key: "revolut", name: "Revolut", official: ["revolut.com"] },
  { key: "wellsfargo", name: "Wells Fargo", official: ["wellsfargo.com"] },
  { key: "tiktok", name: "TikTok", official: ["tiktok.com"] },
];

const TRUSTED_DOMAINS = new Set([
  "google.com", "youtube.com", "github.com", "stackoverflow.com", "wikipedia.org",
  "mozilla.org", "apple.com", "icloud.com", "microsoft.com", "live.com",
  "amazon.com", "cloudflare.com", "openai.com", "anthropic.com", "nytimes.com",
  "bbc.co.uk", "reddit.com", "python.org", "w3.org", "archive.org", "npmjs.com",
  "facebook.com", "instagram.com", "paypal.com", "netflix.com", "linkedin.com",
]);

const REDIRECT_PARAMS = [
  "url", "redirect", "redirect_url", "redirecturi", "next", "dest", "destination",
  "continue", "return", "return_to", "returnurl", "goto", "target", "r", "u",
];

const EXECUTABLE_EXT = /\.(exe|scr|msi|apk|bat|cmd|jar|vbs|ps1|hta)$/i;

export function parseTarget(raw: string): ParsedTarget | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 2048 || /\s/.test(trimmed)) return null;
  const hadExplicitProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed);
  let url: URL;
  try {
    url = new URL(hadExplicitProtocol ? trimmed : `http://${trimmed}`);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  if (!host || !host.includes(".")) return null;
  return { url, hadExplicitProtocol };
}

function registrableDomain(host: string): string {
  const parts = host.split(".");
  return parts.slice(-2).join(".");
}

function isOfficialDomain(official: string[], host: string, reg: string): boolean {
  return official.some((o) => reg === o || host === o || host.endsWith(`.${o}`));
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

export function analyze(target: ParsedTarget, rawInput: string): ScanResult {
  const { url, hadExplicitProtocol } = target;
  const host = url.hostname.toLowerCase();
  const bareHost = host.replace(/^www\./, "");
  const labels = bareHost.split(".");
  const reg = registrableDomain(bareHost);
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const tld = isIpv4 ? "ip-address" : (labels[labels.length - 1] ?? "");
  const haystack = safeDecode(url.href.toLowerCase());
  const normalizedHost = bareHost.replace(/[^a-z0-9]/g, "");

  const factors: RiskFactor[] = [];
  const positives: PositiveSignal[] = [];

  // 1 — Transport security
  if (hadExplicitProtocol && url.protocol === "http:") {
    factors.push({
      id: "no-tls",
      title: "Unencrypted HTTP connection",
      detail:
        "Anything submitted travels in plain text. Legitimate sign-in and payment pages are essentially always HTTPS.",
      severity: "high",
      weight: 20,
    });
  }

  // 2 — Bare IP host
  if (isIpv4 || host.includes(":")) {
    factors.push({
      id: "ip-host",
      title: "Raw IP address instead of a domain",
      detail:
        "The link points straight at a server IP — typical of disposable phishing hosts with no reputation to protect.",
      severity: "critical",
      weight: 36,
    });
  }

  // 3 — Userinfo “@” trick
  if (url.username) {
    factors.push({
      id: "userinfo",
      title: "Credentials embedded in the URL (“@” trick)",
      detail:
        "Browsers ignore everything before “@” — the flashy prefix is decoration, the real host comes after it.",
      severity: "critical",
      weight: 30,
    });
  }

  // 4 — Punycode homograph
  if (host.includes("xn--")) {
    factors.push({
      id: "punycode",
      title: "Punycode / homograph domain",
      detail:
        "“xn--” marks internationalised characters that can visually imitate Latin letters (а vs a) to clone a trusted brand.",
      severity: "high",
      weight: 22,
    });
  }

  // 5 — High-abuse TLD
  if (!isIpv4 && SUSPICIOUS_TLDS.has(tld)) {
    factors.push({
      id: "abusive-tld",
      title: `High-abuse “.${tld}” domain`,
      detail:
        "This top-level domain is free or extremely cheap to register and is disproportionately used for throwaway phishing sites.",
      severity: "medium",
      weight: 16,
    });
  }

  // 6 — Link shortener
  if (SHORTENERS.has(reg)) {
    factors.push({
      id: "shortener",
      title: "Shortener conceals the destination",
      detail: "The real target hides behind a redirect service. Expand the link before deciding to trust it.",
      severity: "high",
      weight: 22,
    });
  }

  // 7 — Brand impersonation in the hostname
  const brandInHost = BRANDS.find(
    (b) => !isOfficialDomain(b.official, host, reg) && normalizedHost.includes(b.key),
  );
  if (brandInHost) {
    factors.push({
      id: "brand-spoof",
      title: `Impersonating “${brandInHost.name}”`,
      detail: `The brand name appears in the address, but the domain is “${reg}”. Real services never host logins outside their own domain.`,
      severity: "critical",
      weight: 34,
    });
  }

  // 8 — Brand referenced off-domain (path/query)
  if (!brandInHost) {
    const brandInPath = BRANDS.find(
      (b) => !isOfficialDomain(b.official, host, reg) && haystack.includes(b.key),
    );
    if (brandInPath) {
      factors.push({
        id: "brand-path",
        title: `“${brandInPath.name}” branding referenced off-domain`,
        detail: `The path borrows ${brandInPath.name} branding while sitting on “${reg}” — a common lure construction.`,
        severity: "medium",
        weight: 12,
      });
    }
  }

  // 9 — Urgency / credential keywords
  const matchedKeywords = KEYWORDS.filter((k) => haystack.includes(k));
  if (matchedKeywords.length > 0) {
    const unique = [...new Set(matchedKeywords)];
    factors.push({
      id: "keywords",
      title: "Credential & urgency keywords",
      detail: `URL contains luring terms: ${unique
        .slice(0, 6)
        .map((k) => `“${k}”`)
        .join(", ")}${unique.length > 6 ? "…" : ""}`,
      severity: unique.length >= 4 ? "high" : "medium",
      weight: Math.min(unique.length * 5, 15),
    });
  }

  // 10 — Deep subdomain nesting
  if (labels.length > 3) {
    factors.push({
      id: "deep-subdomains",
      title: "Deeply nested subdomains",
      detail: `${labels.length} host levels — attackers pile on plausible-looking prefixes like “secure.login.” to confuse the eye.`,
      severity: "low",
      weight: 10,
    });
  }

  // 11 — Hyphen stuffing
  const hyphens = (bareHost.match(/-/g) ?? []).length;
  if (hyphens >= 2) {
    factors.push({
      id: "hyphens",
      title: "Hyphen-stuffed hostname",
      detail: `${hyphens} hyphens in the domain — a common way to smuggle brand words past casual reading.`,
      severity: "low",
      weight: 8,
    });
  }

  // 12 — Excessive length
  if (url.href.length > 120) {
    factors.push({
      id: "length",
      title: "Unusually long URL",
      detail: `${url.href.length} characters — length buries the real host under padding designed to defeat preview bars.`,
      severity: "low",
      weight: 8,
    });
  }

  // 13 — Percent-encoding obfuscation
  const pctCount = (url.href.match(/%[0-9a-f]{2}/gi) ?? []).length;
  if (pctCount >= 3 || url.href.toLowerCase().includes("%25")) {
    factors.push({
      id: "encoding",
      title: "Obfuscated percent-encoding",
      detail: `${pctCount} encoded segment(s) — encoding can disguise path tricks and filter-evasion payloads.`,
      severity: "medium",
      weight: 10,
    });
  }

  // 14 — Non-standard port
  if (url.port && url.port !== "80" && url.port !== "443") {
    factors.push({
      id: "port",
      title: `Non-standard port :${url.port}`,
      detail: "Regular websites serve traffic on 80/443. Odd ports often point at makeshift or malicious servers.",
      severity: "medium",
      weight: 12,
    });
  }

  // 15 — Open-redirect parameter
  const redirectParam = REDIRECT_PARAMS.find((p) => {
    const v = url.searchParams.get(p);
    return v ? v.startsWith("http") : false;
  });
  if (redirectParam) {
    factors.push({
      id: "redirect-param",
      title: "Open-redirect parameter",
      detail: `“?${redirectParam}=” chains you to yet another URL — a favourite way to launder clicks through a semi-trusted site.`,
      severity: "medium",
      weight: 15,
    });
  }

  // 16 — Direct executable download
  if (EXECUTABLE_EXT.test(url.pathname)) {
    factors.push({
      id: "executable",
      title: "Direct executable download",
      detail:
        "The path ends in an executable/script extension. Unsolicited file drops are a classic malware delivery.",
      severity: "high",
      weight: 30,
    });
  }

  // 17 — Machine-generated looking domain label
  const coreLabel = labels.length >= 2 ? labels[labels.length - 2] : bareHost;
  if (coreLabel.length >= 8 && /\d/.test(coreLabel) && /[a-z]/.test(coreLabel)) {
    factors.push({
      id: "randomized",
      title: "Machine-generated looking domain",
      detail: `“${coreLabel}” mixes digits and letters at length — typical of bulk-registered DGA-style phishing hosts.`,
      severity: "medium",
      weight: 10,
    });
  }

  // ---- Scoring -----------------------------------------------------------
  const trusted = TRUSTED_DOMAINS.has(reg);
  const score = Math.min(100, factors.reduce((sum, f) => sum + f.weight, 0));
  const finalScore = trusted ? Math.min(score, 5) : score;

  const verdict: Verdict =
    finalScore >= 70 ? "dangerous" : finalScore >= 45 ? "suspicious" : finalScore >= 22 ? "low" : "safe";

  if (url.protocol === "https:") {
    positives.push({
      title: "TLS-encrypted transport (HTTPS)",
      detail: "Traffic is encrypted in transit — though note this says nothing about who operates the site.",
    });
  }
  if (trusted) {
    positives.push({
      title: "Established, widely recognised domain",
      detail: `“${reg}” matches the curated allowlist of major legitimate services.`,
    });
  }
  if (factors.length === 0) {
    positives.push({
      title: "Zero heuristic triggers",
      detail: "All structural checks came back quiet.",
    });
  }

  return {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    inputUrl: rawInput.trim(),
    href: url.href,
    host: bareHost,
    protocol: hadExplicitProtocol ? url.protocol.replace(":", "") : "",
    tld,
    riskScore: finalScore,
    verdict,
    factors,
    positives,
    scannedAt: Date.now(),
  };
}

export function buildScanLogs(r: ScanResult): LogLine[] {
  const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const worst = r.factors.reduce<Severity | null>(
    (acc, f) => (!acc || rank[f.severity] > rank[acc] ? f.severity : acc),
    null,
  );
  const patternTone: LogTone = !worst ? "ok" : worst === "critical" || worst === "high" ? "bad" : "warn";
  const tlsBad = r.factors.some((f) => f.id === "no-tls");
  const brandBad = r.factors.some((f) => f.id === "brand-spoof");

  return [
    { text: `phishguard scan "${truncate(r.inputUrl, 46)}"`, tone: "cmd" },
    { text: `target acquired ......... ${truncate(r.host, 34)}`, tone: "info" },
    {
      text: `structure ............... ${r.protocol || "scheme:?"} · tld .${r.tld} · ${r.href.length} chars`,
      tone: "info",
    },
    {
      text: tlsBad
        ? "tls inspection .......... ✗ unencrypted channel"
        : "tls inspection .......... ✓ encrypted channel",
      tone: tlsBad ? "bad" : "ok",
    },
    {
      text: brandBad
        ? "brand spoof sweep ....... ✗ IMPERSONATION DETECTED"
        : "brand spoof sweep ....... ✓ no impersonation",
      tone: brandBad ? "bad" : "ok",
    },
    { text: `pattern analysis ........ ${r.factors.length} indicator(s) triggered`, tone: patternTone },
    {
      text: `threat score ............ ${r.riskScore}/100 → ${VERDICT_META[r.verdict].label}`,
      tone: r.verdict === "safe" ? "ok" : r.verdict === "low" ? "warn" : "bad",
    },
  ];
}
