// Threat-feed cross-check against the community Phishing.Database project.
// https://github.com/Phishing-Database/Phishing.Database
//
// The raw lists are fetched from raw.githubusercontent.com (CORS-enabled),
// parsed once per session, and matched entirely locally: exact URL first,
// then host-level. Nothing about the scanned target is sent anywhere.

import type { LogLine, RiskFactor } from "@/lib/phishingEngine";

interface FeedSource {
  label: string;
  file: string;
}

const REPO = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database";
const BRANCHES = ["master", "main"];
const SOURCES: FeedSource[] = [
  { label: "active list", file: "phishing-links-ACTIVE.txt" },
  { label: "new list", file: "phishing-links-NEW.txt" },
];

const FETCH_TIMEOUT_MS = 30_000;
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;

interface FeedCache {
  urls: Set<string>;
  hosts: Set<string>;
  entries: number;
  fetchedAt: number;
}

let cache: FeedCache | null = null;

const HOST_RE = /^[a-z][a-z0-9+.-]*:\/\/([^/?#\s]+)/;
const yieldToUi = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function hostOf(line: string): string | null {
  const match = HOST_RE.exec(line);
  if (!match) return null;
  // strip credentials and port, normalise www
  return match[1].split("@").pop()!.split(":")[0].replace(/^www\./, "");
}

async function fetchText(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    window.clearTimeout(timer);
  }
}

async function fetchSource(source: FeedSource): Promise<string> {
  let lastError = "unreachable";
  for (const branch of BRANCHES) {
    try {
      return await fetchText(`${REPO}/${branch}/${source.file}`);
    } catch (error) {
      lastError = error instanceof Error ? error.message : "network error";
    }
  }
  throw new Error(lastError);
}

/** Ingests a raw list file, yielding to the UI thread periodically. */
async function ingest(text: string, urls: Set<string>, hosts: Set<string>): Promise<number> {
  const lines = text.split("\n");
  let added = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim().toLowerCase();
    if (line && !line.startsWith("#")) {
      urls.add(line.replace(/\/+$/, ""));
      const host = hostOf(line);
      if (host) hosts.add(host);
      added++;
    }
    if ((i & 16383) === 16383) await yieldToUi();
  }
  return added;
}

async function loadFeed(onProgress?: (line: LogLine) => void): Promise<FeedCache> {
  if (cache && Date.now() - cache.fetchedAt < CACHE_TTL_MS) return cache;

  const urls = new Set<string>();
  const hosts = new Set<string>();

  for (const source of SOURCES) {
    try {
      const text = await fetchSource(source);
      const added = await ingest(text, urls, hosts);
      onProgress?.({
        text: `feed sync · ${source.label}: ${added.toLocaleString()} entries`,
        tone: "info",
      });
    } catch (error) {
      onProgress?.({
        text: `feed sync · ${source.label}: ✗ ${error instanceof Error ? error.message : "failed"}`,
        tone: "warn",
      });
    }
  }

  if (urls.size === 0) throw new Error("feed unavailable");

  cache = { urls, hosts, entries: urls.size, fetchedAt: Date.now() };
  return cache;
}

export type FeedOutcome = { error: string } | { factor: RiskFactor | null; entries: number };

/**
 * Cross-checks a scan target against the Phishing.Database feed.
 * Never throws — failures come back as `{ error }`.
 */
export async function checkPhishingDatabase(
  href: string,
  host: string,
  onProgress?: (line: LogLine) => void,
): Promise<FeedOutcome> {
  try {
    const feed = await loadFeed(onProgress);

    // exact-URL match (normalised: lowercase, fragment stripped, trailing slash stripped)
    const normalized = href.toLowerCase().split("#")[0].replace(/\/+$/, "");
    if (feed.urls.has(normalized)) {
      return {
        factor: {
          id: "db-url-hit",
          source: "feed",
          title: "Listed in Phishing.Database (exact URL)",
          detail:
            "This exact address appears in the community-maintained phishing feed — reported and verified as malicious.",
          severity: "critical",
          weight: 40,
        },
        entries: feed.entries,
      };
    }

    // host-level match
    const bareHost = host.toLowerCase().replace(/^www\./, "");
    if (feed.hosts.has(bareHost)) {
      return {
        factor: {
          id: "db-host-hit",
          source: "feed",
          title: "Host found in Phishing.Database",
          detail: `Other addresses on ${bareHost} are already listed in the feed — the domain itself carries a phishing record.`,
          severity: "critical",
          weight: 34,
        },
        entries: feed.entries,
      };
    }

    return { factor: null, entries: feed.entries };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "feed unavailable" };
  }
}
