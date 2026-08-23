import { useRef, useState, type ReactNode } from "react";
import { History, Lightbulb, Radar } from "lucide-react";
import ScannerForm from "@/components/ScannerForm";
import TerminalOutput from "@/components/TerminalOutput";
import VerdictCard from "@/components/VerdictCard";
import RiskBreakdown from "@/components/RiskBreakdown";
import ScanHistoryPanel from "@/components/ScanHistoryPanel";
import TipsSection from "@/components/TipsSection";
import { useScanHistory } from "@/hooks/useScanHistory";
import {
  analyze,
  buildScanLogs,
  parseTarget,
  type LogLine,
  type ScanResult,
} from "@/lib/phishingEngine";

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

    const res = analyze(parsed, input);
    const lines = buildScanLogs(res);
    for (let i = 0; i < lines.length; i++) {
      await sleep(i === 0 ? 180 : 300);
      if (scanSeq.current !== seq) return;
      setLogs((prev) => [...prev, lines[i]]);
    }
    await sleep(320);
    if (scanSeq.current !== seq) return;

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
            [ OFFLINE HEURISTIC ENGINE ]
          </p>
          <h1 className="mx-auto mt-4 max-w-2xl text-4xl font-extrabold leading-[1.08] tracking-tight text-fog sm:text-5xl">
            Scan the link.
            <br />
            <span className="text-glow text-neon">Before it scans you.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-sm leading-relaxed text-dim">
            Paste any URL and PhishGuard dissects it for phishing fingerprints — brand spoofing,
            homograph domains, bare IPs, sneaky redirects and more. Nothing ever leaves your device.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {["17 HEURISTIC CHECKS", "0 NETWORK CALLS", "100% LOCAL"].map((stat) => (
              <span
                key={stat}
                className="rounded-full border border-edge bg-panel px-3 py-1 text-[10px] font-medium tracking-[0.18em] text-dim"
              >
                {stat}
              </span>
            ))}
          </div>
        </section>

        {/* scanner */}
        <section className="rounded-2xl border border-edge bg-panel p-4 shadow-[0_0_80px_-40px_rgba(0,255,156,0.4)] sm:p-6">
          <ScannerForm scanning={phase === "scanning"} error={formError} onScan={runScan} />
          <div className="mt-5">
            <TerminalOutput logs={logs} scanning={phase === "scanning"} />
          </div>
        </section>

        {/* results */}
        {result && (
          <div ref={resultRef} className="scroll-mt-24 space-y-6 pt-12">
            <VerdictCard result={result} />
            <RiskBreakdown result={result} />
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
          PhishGuard runs purely structural heuristics in your browser — no site is contacted and no
          data leaves your device. A clean verdict is not a guarantee: always pair automated checks
          with your own judgement.
        </p>
      </footer>
    </div>
  );
}
