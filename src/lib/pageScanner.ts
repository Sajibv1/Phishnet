// Live-page deep scan: retrieves the target's HTML through public CORS relays
// and dissects the DOM for content-level phishing tricks. Parsing happens in a
// fully inert DOMParser document — no script executes, nothing is submitted.

import {
  BRANDS,
  isOfficialDomain,
  registrableDomain,
  type LogLine,
  type PageReport,
  type RiskFactor,
} from "@/lib/phishingEngine";

interface FetchedPage {
  html: string;
  bytes: number;
  via: string;
  durationMs: number;
}

const RELAYS: Array<{ name: string; build: (url: string) => string }> = [
  {
    name: "allorigins",
    build: (u) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  },
  {
    name: "codetabs",
    build: (u) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  },
  {
    name: "corsproxy",
    build: (u) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
  },
];

const RELAY_TIMEOUT_MS = 9000;

/** Fetches the raw HTML of a target URL, trying relays in order until one answers. */
export async function fetchPageHtml(target: string): Promise<FetchedPage> {
  let lastError = "relay unreachable";

  for (const relay of RELAYS) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), RELAY_TIMEOUT_MS);
    const started = performance.now();
    try {
      const res = await fetch(relay.build(target), { signal: controller.signal });
      if (!res.ok) {
        lastError = `${relay.name} → HTTP ${res.status}`;
        continue;
      }
      const html = await res.text();
      if (!html) {
        lastError = `${relay.name} → empty response`;
        continue;
      }
      return {
        html,
        bytes: html.length,
        via: relay.name,
        durationMs: Math.round(performance.now() - started),
      };
    } catch (error) {
      lastError =
        error instanceof DOMException && error.name === "AbortError"
          ? `${relay.name} → timed out`
          : `${relay.name} → network error`;
    } finally {
      window.clearTimeout(timer);
    }
  }

  throw new Error(lastError);
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

/**
 * Dissects fetched HTML inside an inert document and returns content-level
 * risk factors plus a snapshot report for the sandbox panel.
 */
export function analyzePage(
  html: string,
  pageUrl: string,
): { factors: RiskFactor[]; report: PageReport } {
  const factors: RiskFactor[] = [];

  let base: URL;
  try {
    base = new URL(pageUrl);
  } catch {
    return { factors, report: { status: "failed", reason: "invalid target" } };
  }

  const doc = new DOMParser().parseFromString(html, "text/html");
  const pageReg = registrableDomain(base.hostname.replace(/^www\./, ""));
  const offDomain = (candidate: URL) =>
    registrableDomain(candidate.hostname.replace(/^www\./, "")) !== pageReg;
  const absolute = (value: string): URL | null => {
    try {
      return new URL(value, base);
    } catch {
      return null;
    }
  };

  const title = (doc.title || "").trim().slice(0, 140);
  const description = (
    doc.querySelector('meta[name="description" i]')?.getAttribute("content") ?? ""
  )
    .trim()
    .slice(0, 220);

  // C1 — credential forms
  let offDomainForms = 0;
  let onDomainForms = 0;
  doc.querySelectorAll("form").forEach((form) => {
    if (!form.querySelector('input[type="password" i]')) return;
    const action = form.getAttribute("action") ?? "";
    const resolved = action ? absolute(action) : base;
    if (resolved && offDomain(resolved)) offDomainForms++;
    else onDomainForms++;
  });
  if (offDomainForms > 0) {
    factors.push({
      id: "cred-form-offdomain",
      source: "content",
      title: "Credential form posts OFF-domain",
      detail: `${offDomainForms} password field${offDomainForms > 1 ? "s" : ""} inside a form whose action leaves “${pageReg}” — textbook credential harvesting.`,
      severity: "critical",
      weight: 32,
    });
  } else if (onDomainForms > 0) {
    factors.push({
      id: "cred-form-local",
      source: "content",
      title: "Password field on page",
      detail: `${onDomainForms} login form${onDomainForms > 1 ? "s" : ""} posting within the same domain — normal for sign-in pages, but verify the address before typing.`,
      severity: "low",
      weight: 6,
    });
  }

  // C2 — meta-refresh redirect
  const refresh = doc.querySelector('meta[http-equiv="refresh" i]')?.getAttribute("content") ?? "";
  const refreshTarget = refresh.match(/url=(.+)$/i)?.[1]?.trim().replace(/["']/g, "");
  if (refreshTarget) {
    const resolved = absolute(refreshTarget);
    if (resolved && offDomain(resolved)) {
      factors.push({
        id: "meta-refresh",
        source: "content",
        title: "Meta-refresh redirect trap",
        detail: `The page silently forwards visitors to ${truncate(resolved.hostname, 40)} — a classic way to bounce scanners onto the real lure.`,
        severity: "high",
        weight: 18,
      });
    }
  }

  // C3 — hidden / external iframes
  let hiddenFrames = 0;
  let externalFrames = 0;
  doc.querySelectorAll("iframe").forEach((frame) => {
    const style = frame.getAttribute("style") ?? "";
    const width = frame.getAttribute("width") ?? "";
    const height = frame.getAttribute("height") ?? "";
    const concealed =
      frame.hasAttribute("hidden") ||
      /display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0/i.test(style) ||
      width === "0" ||
      height === "0";
    const src = frame.getAttribute("src");
    const resolved = src ? absolute(src) : null;
    if (concealed) hiddenFrames++;
    else if (resolved && offDomain(resolved)) externalFrames++;
  });
  if (hiddenFrames > 0) {
    factors.push({
      id: "hidden-iframes",
      source: "content",
      title: "Hidden iframe injection",
      detail: `${hiddenFrames} invisible iframe${hiddenFrames > 1 ? "s" : ""} embedded — typical of drive-by loaders, click-jacking or silent tracking.`,
      severity: "high",
      weight: 16,
    });
  }
  if (externalFrames > 0) {
    factors.push({
      id: "external-iframes",
      source: "content",
      title: "Third-party frames embedded",
      detail: `${externalFrames} visible iframe${externalFrames > 1 ? "s" : ""} hosted on other domains.`,
      severity: "low",
      weight: 5,
    });
  }

  // C4 — favicon cloaking
  const foreignFavicon = [...doc.querySelectorAll('link[rel*="icon" i]')]
    .map((link) => link.getAttribute("href"))
    .filter((href): href is string => !!href)
    .map(absolute)
    .find((url) => url && offDomain(url));
  if (foreignFavicon) {
    factors.push({
      id: "favicon-offdomain",
      source: "content",
      title: "Tab icon loaded from another domain",
      detail: `The favicon is served from ${foreignFavicon.hostname} — a cloaking trick that makes the browser tab imitate a trusted site.`,
      severity: "medium",
      weight: 10,
    });
  }

  // C5 — brand claimed in page title
  const titleLower = title.toLowerCase();
  const brandClaim = BRANDS.find(
    (brand) =>
      !isOfficialDomain(brand.official, base.hostname.toLowerCase(), pageReg) &&
      titleLower.includes(brand.name.toLowerCase()),
  );
  if (brandClaim) {
    factors.push({
      id: "brand-title",
      source: "content",
      title: `“${brandClaim.name}” claimed in page title`,
      detail: `The tab reads like ${brandClaim.name}, but the domain is “${pageReg}”. Legitimate brands don't operate look-alike hosts.`,
      severity: "critical",
      weight: 20,
    });
  }

  // C6/C7 — inline script inspection
  const inlineJs = [...doc.querySelectorAll("script:not([src])")]
    .map((node) => node.textContent ?? "")
    .join("\n")
    .slice(0, 200_000);

  const obfuscation = inlineJs.match(/eval\(|document\.write\(|unescape\(|atob\(|fromCharCode/g);
  if (obfuscation && obfuscation.length >= 2) {
    factors.push({
      id: "obfuscated-js",
      source: "content",
      title: "Obfuscated inline JavaScript",
      detail: `${obfuscation.length} obfuscation primitive(s) (eval/atob/fromCharCode…) — often used to hide redirect and hook payloads from review.`,
      severity: "medium",
      weight: 12,
    });
  }

  if (/location(?:\.href)?\s*=\s*["']https?:\/\//i.test(inlineJs)) {
    factors.push({
      id: "scripted-redirect",
      source: "content",
      title: "Scripted redirect",
      detail:
        "Inline JavaScript steers visitors to another URL — what you see and what an automated inspector sees may differ.",
      severity: "medium",
      weight: 10,
    });
  }

  // visible-text excerpt (scripts/styles stripped)
  doc.querySelectorAll("script, style, noscript, template").forEach((node) => node.remove());
  const excerpt = (doc.body?.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 600);

  return {
    factors,
    report: { status: "fetched", title, description, excerpt },
  };
}

/** Turns content findings into terminal log lines for the deep-scan stage. */
export function summarizeFindings(factors: RiskFactor[]): LogLine[] {
  const top = [...factors].sort((a, b) => b.weight - a.weight).slice(0, 3);
  const lines: LogLine[] = top.map((factor) => ({
    text: `page probe · ${factor.title}`,
    tone:
      factor.severity === "critical" || factor.severity === "high"
        ? "bad"
        : factor.severity === "medium"
          ? "warn"
          : "ok",
  }));
  lines.push({
    text: `deep scan ............... ${factors.length} content finding(s)`,
    tone: factors.some((f) => f.severity === "critical" || f.severity === "high")
      ? "bad"
      : factors.length > 0
        ? "warn"
        : "ok",
  });
  return lines;
}
