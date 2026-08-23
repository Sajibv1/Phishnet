import type { LogLine } from "@/lib/phishingEngine";

const TONE_CLASS: Record<LogLine["tone"], string> = {
  cmd: "font-semibold text-fog",
  info: "text-dim",
  ok: "text-neon",
  warn: "text-warn",
  bad: "text-tox",
};

interface Props {
  logs: LogLine[];
  scanning: boolean;
}

export default function TerminalOutput({ logs, scanning }: Props) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-edge bg-[#060b0d]">
      {/* window chrome */}
      <div className="flex items-center gap-1.5 border-b border-edge/80 px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-tox/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-warn/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-neon/70" />
        <span className="ml-3 text-[10px] tracking-[0.22em] text-dim">scan://phishguard/engine</span>
      </div>

      <div className="relative min-h-[176px] p-4 text-[12.5px] leading-[1.9] sm:text-[13px]">
        {scanning && (
          <span className="animate-sweep pointer-events-none absolute left-0 right-0 h-px bg-neon/50 shadow-[0_0_14px_rgba(0,255,156,0.7)]" />
        )}

        {logs.length === 0 && !scanning ? (
          <p className="text-dim">
            $ awaiting target — paste a URL above
            <span className="animate-blink ml-1 text-neon">▌</span>
          </p>
        ) : (
          logs.map((line, i) => (
            <p key={`${i}-${line.text}`} className={`animate-fade-up ${TONE_CLASS[line.tone]}`}>
              <span className="mr-2 select-none text-dim/70">{line.tone === "cmd" ? "$" : "›"}</span>
              {line.text}
              {scanning && i === logs.length - 1 && (
                <span className="animate-blink ml-1 text-neon">▌</span>
              )}
            </p>
          ))
        )}
      </div>
    </div>
  );
}
