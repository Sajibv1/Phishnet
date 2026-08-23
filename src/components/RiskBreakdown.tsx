import { ShieldCheck } from "lucide-react";
import { SEVERITY_STYLE, type ScanResult } from "@/lib/phishingEngine";

export default function RiskBreakdown({ result }: { result: ScanResult }) {
  const factors = [...result.factors].sort((a, b) => b.weight - a.weight);

  return (
    <div className="space-y-6">
      {/* triggered indicators */}
      <section className="rounded-2xl border border-edge bg-panel p-5 sm:p-6">
        <header className="mb-4 flex items-center justify-between">
          <h3 className="text-[11px] font-bold tracking-[0.26em] text-fog">TRIGGERED INDICATORS</h3>
          <span className="rounded-full border border-edge px-2.5 py-0.5 text-[10px] tracking-widest text-dim">
            {factors.length} FOUND
          </span>
        </header>

        {factors.length === 0 ? (
          <div className="flex items-center gap-3 rounded-lg border border-neon/25 bg-neon/5 p-4">
            <ShieldCheck className="h-5 w-5 shrink-0 text-neon" />
            <p className="text-xs leading-relaxed text-dim">
              None of the structural checks flagged this URL.
            </p>
          </div>
        ) : (
          <ul className="space-y-2.5">
            {factors.map((factor, i) => {
              const severity = SEVERITY_STYLE[factor.severity];
              return (
                <li
                  key={factor.id}
                  className="animate-fade-up rounded-lg border border-edge bg-[#070d10] p-3.5"
                  style={{
                    animationDelay: `${i * 70}ms`,
                    borderLeft: `3px solid ${severity.color}`,
                  }}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className="rounded px-1.5 py-0.5 text-[9px] font-extrabold tracking-[0.18em]"
                      style={{ backgroundColor: `${severity.color}1f`, color: severity.color }}
                    >
                      {severity.label}
                    </span>
                    <span className="text-sm font-semibold text-fog">{factor.title}</span>
                    <span
                      className="ml-auto text-[11px] font-bold tabular-nums"
                      style={{ color: severity.color }}
                    >
                      +{factor.weight}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-dim">{factor.detail}</p>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {/* positive signals */}
      {result.positives.length > 0 && (
        <section className="rounded-2xl border border-edge bg-panel p-5 sm:p-6">
          <header className="mb-4">
            <h3 className="text-[11px] font-bold tracking-[0.26em] text-fog">POSITIVE SIGNALS</h3>
          </header>
          <ul className="space-y-2.5">
            {result.positives.map((signal) => (
              <li
                key={signal.title}
                className="flex items-start gap-3 rounded-lg border border-neon/20 bg-neon/[0.04] p-3.5"
              >
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-neon" />
                <div>
                  <p className="text-sm font-semibold text-fog">{signal.title}</p>
                  <p className="mt-0.5 text-xs leading-relaxed text-dim">{signal.detail}</p>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
