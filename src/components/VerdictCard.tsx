import { useEffect, useState } from "react";
import { Check, Copy, ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX } from "lucide-react";
import { VERDICT_META, type ScanResult, type Verdict } from "@/lib/phishingEngine";

const VERDICT_ICON: Record<Verdict, typeof ShieldCheck> = {
  safe: ShieldCheck,
  low: ShieldQuestion,
  suspicious: ShieldAlert,
  dangerous: ShieldX,
};

function useCountUp(target: number, duration = 900): number {
  const [value, setValue] = useState(0);

  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(eased * target));
      if (progress < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);

  return value;
}

function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1.5 overflow-hidden rounded-md border border-edge bg-[#070d10] px-2.5 py-1.5 text-[11px]">
      <span className="shrink-0 tracking-[0.16em] text-dim">{label}</span>
      <span className="truncate font-semibold text-fog">{value}</span>
    </span>
  );
}

export default function VerdictCard({ result }: { result: ScanResult }) {
  const meta = VERDICT_META[result.verdict];
  const Icon = VERDICT_ICON[result.verdict];
  const shownScore = useCountUp(result.riskScore);
  const [copied, setCopied] = useState(false);
  const circumference = 2 * Math.PI * 56;

  const copyReport = async () => {
    const lines = [
      `PhishGuard report — ${new Date(result.scannedAt).toLocaleString()}`,
      `URL: ${result.inputUrl}`,
      `Threat score: ${result.riskScore}/100 (${meta.label})`,
      ...(result.page?.status === "fetched"
        ? [
            "",
            `Live page: “${result.page.title ?? "(untitled)"}” (${result.page.bytes ?? 0} bytes via ${result.page.via ?? "relay"})`,
          ]
        : []),
      "",
      ...result.factors.map(
        (f) =>
          `- [${f.severity.toUpperCase()}]${f.source === "content" ? " [page]" : ""} ${f.title}: ${f.detail}`,
      ),
    ];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard unavailable — ignore
    }
  };

  return (
    <section
      className="animate-fade-up rounded-2xl border bg-panel p-5 sm:p-6"
      style={{ borderColor: `${meta.color}40`, boxShadow: `0 0 70px -35px ${meta.color}` }}
    >
      <div className="flex flex-col items-center gap-6 sm:flex-row sm:gap-8">
        {/* score gauge */}
        <div className="relative shrink-0">
          <svg viewBox="0 0 140 140" className="h-40 w-40 -rotate-90">
            <circle cx="70" cy="70" r="56" fill="none" strokeWidth="10" className="stroke-edge" />
            <circle
              cx="70"
              cy="70"
              r="56"
              fill="none"
              strokeWidth="10"
              stroke={meta.color}
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={circumference * (1 - shownScore / 100)}
              style={{ transition: "stroke-dashoffset 120ms linear" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-4xl font-extrabold tabular-nums text-fog">{shownScore}</span>
            <span className="mt-0.5 text-[10px] tracking-[0.3em] text-dim">/ 100</span>
          </div>
        </div>

        <div className="min-w-0 flex-1 text-center sm:text-left">
          <div className="flex items-center justify-center gap-2.5 sm:justify-start">
            <Icon className="h-6 w-6 shrink-0" style={{ color: meta.color }} />
            <h2 className="text-2xl font-extrabold tracking-wide" style={{ color: meta.color }}>
              {meta.label}
            </h2>
          </div>
          <p className="mt-2 text-sm leading-relaxed text-dim">{meta.blurb}</p>

          <div className="mt-4 flex flex-wrap justify-center gap-2 sm:justify-start">
            <Chip label="HOST" value={result.host} />
            <Chip label="SCHEME" value={result.protocol || "unknown"} />
            <Chip label="TLD" value={`.${result.tld}`} />
            <Chip label="LENGTH" value={`${result.href.length}ch`} />
          </div>

          <button
            onClick={copyReport}
            className="mt-5 inline-flex items-center gap-2 rounded-md border border-edge bg-raise px-3.5 py-2 text-[11px] font-semibold tracking-[0.14em] text-dim transition hover:border-neon/40 hover:text-neon"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-neon" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? "COPIED" : "COPY REPORT"}
          </button>
        </div>
      </div>
    </section>
  );
}
