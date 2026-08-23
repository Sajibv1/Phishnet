import { useRef, useState, type ReactNode } from "react";
import { History, Lightbulb, Radar } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import ScannerForm from "@/components/ScannerForm";
import TerminalOutput from "@/components/TerminalOutput";
import VerdictCard from "@/components/VerdictCard";
import RiskBreakdown from "@/components/RiskBreakdown";
import SandboxPanel from "@/components/SandboxPanel";
import ScanHistoryPanel from "@/components/ScanHistoryPanel";
import TipsSection from "@/components/TipsSection";
import { useScanHistory } from "@/hooks/useScanHistory";
import {
  analyze,
  applyPageFindings,
  buildScanLogs,
  parseTarget,
  rescore,
  type LogLine,
  type ScanResult,
} from "@/lib/phishingEngine";
import { analyzePage, fetchPageHtml, summarizeFindings } from "@/lib/pageScanner";
import { checkPhishingDatabase, type FeedOutcome } from "@/lib/threatFeed";

type Phase = "idle" | "scanning" | "done";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function SectionHeading({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <div className="mb-4 flex items-center gap-2.5">
      {icon}
      <h2 className="text-xs font-bold tracking-[0.28em] text-fog">{title}</h2>
      <span className="h-px flex-1 bg-edge" />
    </div>
  );
}

export default function Index() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [deepScan, setDeepScan] = useState(true);
  const [feedCheck, setFeedCheck] = useState(true);
  const { items: history, add: addScan, clear: clearHistory } = useScanHistory();
  const resultRef = useRef<HTMLDivElement>(null);
  const scanSeq = useRef(0);

  const scrollToResult = () => {
    window.setTimeout(
      () => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }),
      80,
    );
  };

  const runScan = async (input: string) => {
    const parsed = parseTarget(input);
    if (!parsed) {
      setFormError("That doesn't parse as a URL. Try something like https://example.com/login");
      return;
    }
    setFormError(null);
    const seq = ++scanSeq.current;
    setPhase("scanning");
    setLogs([]);
    setResult(null);

    // stage 1 — structural analysis (fully offline)
    const res = analyze(parsed, input);
    const lines = buildScanLogs(res);
    for (let i = 0; i < lines.length; i++) {
      await sleep(i === 0 ? 180 : 300);
      if (scanSeq.current !== seq) return;
      setLogs((prev) => [...prev, lines[i]]);
    }
    await sleep(320);
    if (scanSeq.current !== seq) return;

    // stage 2a — kick off threat-feed sync in the background so it overlaps the deep scan
    const feedPromise: Promise<FeedOutcome | null> =
      feedCheck && /^https?:$/.test(parsed.url.protocol)
        ? checkPhishingDatabase(res.href, res.host, (line) => {
            if (scanSeq.current === seq) setLogs((prev) => [...prev, line]);
          })
        : Promise.resolve(null);

    // stage 2b — deep scan: retrieve & dissect the live page
    if (deepScan && /^https?:$/.test(parsed.url.protocol)) {
      setLogs((prev) => [
        ...prev,
        { text: "sandbox relay .......... requesting live page", tone: "info" },
      ]);
      await sleep(280);
      if (scanSeq.current !== seq) return;
      try {
        const page = await fetchPageHtml(res.href);
        if (scanSeq.current !== seq) return;
        setLogs((prev) => [
          ...prev,
          {
            text: `payload received ....... ${page.bytes.toLocaleString()} bytes via ${page.via}`,
            tone: "ok",
          },
        ]);

        const { factors: contentFactors, report } = analyzePage(page.html, res.href);
        applyPageFindings(res, contentFactors, {
          ...report,
          via: page.via,
          bytes: page.bytes,
          durationMs: page.durationMs,
        });

        await sleep(300);
        if (scanSeq.current !== seq) return;
        for (const line of summarizeFindings(contentFactors)) {
          await sleep(260);
          if (scanSeq.current !== seq) return;
          setLogs((prev) => [...prev, line]);
        }
      } catch (error) {
        if (scanSeq.current !== seq) return;
        const reason = error instanceof Error ? error.message : "network error";
        applyPageFindings(res, [], { status: "failed", reason });
        setLogs((prev) => [
          ...prev,
          { text: `sandbox relay .......... ✗ ${reason}`, tone: "warn" },
          { text: "continuing with structural verdict", tone: "info" },
        ]);
      }
    }

    // stage 2c — report the threat-feed verdict
    const feed = await feedPromise;
    if (scanSeq.current !== seq) return;
    if (feed) {
      setLogs((prev) => [
        ...prev,
        { text: "threat feed ............. cross-checking Phishing.Database", tone: "info" },
      ]);
      await sleep(220);
      if (scanSeq.current !== seq) return;

      if ("error" in feed) {
        setLogs((prev) => [
          ...prev,
          { text: `threat feed ............. ✗ ${feed.error}`, tone: "warn" },
        ]);
      } else {
        setLogs((prev) => [
          ...prev,
          {
            text: `threat feed ............. ${feed.entries.toLocaleString()} entries checked`,
            tone: "info",
          },
        ]);
        if (feed.factor) {
          res.factors.push(feed.factor);
          rescore(res);
          setLogs((prev) => [
            ...prev,
            { text: "database match .......... ✗ LISTED — CONFIRMED PHISHING", tone: "bad" },
          ]);
        } else {
          res.positives.push({
            title: "Not listed in Phishing.Database",
            detail: `Checked against ${feed.entries.toLocaleString()} known phishing URLs from the community feed.`,
          });
          setLogs((prev) => [
            ...prev,
            { text: "database match .......... ✓ not listed", tone: "ok" },
          ]);
        }
      }
    }

    setResult(res);
    setPhase("done");
    addScan(res);
    scrollToResult();
  };

  const viewFromHistory = (item: ScanResult) => {
    scanSeq.current++;
    setResult(item);
    setLogs(buildScanLogs(item));
    setFormError(null);
    setPhase("done");
    scrollToResult();
  };

  return (
    <div className="relative min-h-screen overflow-x-clip">
      {/* backdrop texture */}
      <div aria-hidden className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-[520px]" />
      <div aria-hidden className="scanlines pointer-events-none fixed inset-0 z-50" />

      <header className="sticky top-0 z-40 border-b border-edge/80 bg-void/85 backdrop-blur">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-4 py-3.5">
          <div className="flex items-center gap-3">
            <div className="glow-neon grid h-9 w-9 place-items-center rounded-lg border border-neon/40 bg-neon/10">
              <Radar className="h-5 w-5 text-neon" />
            </div>
            <div className="leading-none">
              <p className="text-sm font-extrabold tracking-[0.18em] text-fog">
                PHISH<span className="text-neon">GUARD</span>
              </p>
              <p className="mt-1 text-[10px] tracking-[0.22em] text-dim">LINK THREAT SCANNER</p>
            </div>
          </div>
          <div className="hidden items-center gap-2 rounded-full border border-neon/25 bg-neon/5 px-3 py-1.5 sm:flex">
            <span className="animate-pulse-dot h-1.5 w-1.5 rounded-full bg-neon" />
            <span className="text-[10px] font-semibold tracking-[0.2em] text-neon">
              ENGINE ONLINE
            </span>
          </div>
        </div>
      </header>

      <main className="relative mx-auto max-w-4xl px-4">
        {/* hero */}
        <section className="pb-10 pt-12 text-center sm:pt-16">
          <p className="text-[11px] font-semibold tracking-[0.34em] text-neon">
            [ SANDBOXED HEURISTIC ENGINE ]
          </p>
          <h1 className="mx-auto mt-4 max-w-2xl text-4xl font-extrabold leading-[1.08] tracking-tight text-fog sm:text-5xl">
            Scan the link.
            <br />
            <span className="text-glow text-neon">Before it scans you.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-sm leading-relaxed text-dim">
            Paste any URL and PhishGuard dissects it for phishing fingerprints, opens the live page
            in a sandbox to hunt credential traps, and cross-checks the community Phishing.Database
            feed. Nothing is executed on your device.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {["17 STRUCTURAL CHECKS", "+9 LIVE-PAGE CHECKS", "PHISHING.DATABASE FEED"].map(
              (stat) => (
                <span
                  key={stat}
                  className="rounded-full border border-edge bg-panel px-3 py-1 text-[10px] font-medium tracking-[0.18em] text-dim"
                >
                  {stat}
                </span>
              ),
            )}
          </div>
        </section>

        {/* scanner */}
        <section className="rounded-2xl border border-edge bg-panel p-4 shadow-[0_0_80px_-40px_rgba(0,255,156,0.4)] sm:p-6">
          <ScannerForm scanning={phase === "scanning"} error={formError} onScan={runScan} />

          <div className="mt-4 space-y-2">
            <div className="flex items-center justify-between gap-3 rounded-lg border border-edge bg-[#070d10] px-3.5 py-2.5">
              <div>
                <p className="text-[11px] font-bold tracking-[0.14em] text-fog">DEEP SCAN</p>
                <p className="mt-0.5 text-[10px] leading-relaxed text-dim">
                  Fetch the live page through a public relay &amp; dissect its HTML for credential
                  traps.
                </p>
              </div>
              <Switch
                checked={deepScan}
                onCheckedChange={setDeepScan}
                aria-label="Toggle deep scan"
                disabled={phase === "scanning"}
              />
            </div>
            <div className="flex items-center justify-between gap-3 rounded-lg border border-edge bg-[#070d10] px-3.5 py-2.5">
              <div>
                <p className="text-[11px] font-bold tracking-[0.14em] text-fog">THREAT FEED</p>
                <p className="mt-0.5 text-[10px] leading-relaxed text-dim">
                  Cross-check against the community Phishing.Database feed — synced once per
                  session.
                </p>
              </div>
              <Switch
                checked={feedCheck}
                onCheckedChange={setFeedCheck}
                aria-label="Toggle threat feed check"
                disabled={phase === "scanning"}
              />
            </div>
          </div>

          <div className="mt-5">
            <TerminalOutput logs={logs} scanning={phase === "scanning"} />
          </div>
        </section>

        {/* results */}
        {result && (
          <div ref={resultRef} className="scroll-mt-24 space-y-6 pt-12">
            <VerdictCard result={result} />
            <RiskBreakdown result={result} />
            <SandboxPanel result={result} />
          </div>
        )}

        {/* history */}
        <section className="pt-14">
          <SectionHeading icon={<History className="h-4 w-4 text-neon" />} title="SCAN HISTORY" />
          <ScanHistoryPanel items={history} onSelect={viewFromHistory} onClear={clearHistory} />
        </section>

        {/* tips */}
        <section className="pt-14">
          <SectionHeading icon={<Lightbulb className="h-4 w-4 text-neon" />} title="SPOT IT YOURSELF" />
          <TipsSection />
        </section>
      </main>

      <footer className="mt-16 border-t border-edge/70 py-8">
        <p className="mx-auto max-w-2xl px-4 text-center text-[11px] leading-relaxed text-dim">
          Structural checks run fully offline. With Deep Scan enabled, the target page is fetched
          once through a public relay and dissected in your browser — nothing is executed,
          submitted, or stored beyond this device. The optional threat feed downloads the community
          Phishing.Database lists once per session and matches locally. A clean verdict is not a
          guarantee: always pair automated checks with your own judgement.
        </p>
      </footer>
    </div>
  );
}
