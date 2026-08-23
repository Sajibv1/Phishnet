import { useState } from "react";
import { AppWindow, FileText, TriangleAlert, X } from "lucide-react";
import type { ScanResult } from "@/lib/phishingEngine";

export default function SandboxPanel({ result }: { result: ScanResult }) {
  const page = result.page;
  const [frameOpen, setFrameOpen] = useState(false);

  if (!page) return null;

  if (page.status === "failed") {
    return (
      <section className="rounded-2xl border border-warn/25 bg-warn/[0.04] p-5">
        <div className="flex items-start gap-3">
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-warn" />
          <div>
            <h3 className="text-sm font-bold tracking-wide text-fog">LIVE PAGE UNREACHABLE</h3>
            <p className="mt-1 text-xs leading-relaxed text-dim">
              The sandboxed relay couldn't retrieve content ({page.reason}). The target may block
              automated access or be offline — the structural verdict above still stands.
            </p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="rounded-2xl border border-edge bg-panel p-5 sm:p-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <AppWindow className="h-4 w-4 text-neon" />
          <h3 className="text-[11px] font-bold tracking-[0.26em] text-fog">SANDBOX SNAPSHOT</h3>
        </div>
        <div className="flex flex-wrap gap-2 text-[10px] tracking-widest text-dim">
          <span className="rounded-full border border-edge px-2.5 py-1 tabular-nums">
            {(page.bytes ?? 0).toLocaleString()} B
          </span>
          <span className="rounded-full border border-edge px-2.5 py-1 tabular-nums">
            {page.durationMs ?? 0} MS
          </span>
          <span className="rounded-full border border-edge px-2.5 py-1">
            VIA {page.via?.toUpperCase()}
          </span>
        </div>
      </header>

      {page.title && (
        <p className="mt-4 break-words text-sm font-bold text-fog">“{page.title}”</p>
      )}
      {page.description && (
        <p className="mt-1 break-words text-xs leading-relaxed text-dim">{page.description}</p>
      )}

      {page.excerpt && (
        <div className="mt-4">
          <p className="mb-1.5 flex items-center gap-1.5 text-[10px] tracking-[0.2em] text-dim">
            <FileText className="h-3 w-3" />
            VISIBLE TEXT EXCERPT
          </p>
          <div className="max-h-40 overflow-y-auto rounded-lg border border-edge bg-[#060b0d] p-3.5 text-[11px] leading-relaxed text-dim">
            {page.excerpt || "(no readable text — likely image-only or fully scripted content)"}
          </div>
        </div>
      )}

      <div className="mt-4">
        {!frameOpen ? (
          <button
            onClick={() => setFrameOpen(true)}
            className="inline-flex items-center gap-2 rounded-md border border-edge bg-raise px-3.5 py-2 text-[11px] font-semibold tracking-[0.14em] text-dim transition hover:border-neon/40 hover:text-neon"
          >
            <AppWindow className="h-3.5 w-3.5" />
            LOAD SANDBOXED FRAME
          </button>
        ) : (
          <div>
            <iframe
              src={result.href}
              sandbox=""
              referrerPolicy="no-referrer"
              title="Sandboxed page preview"
              className="h-[420px] w-full rounded-lg border border-edge bg-white"
            />
            <button
              onClick={() => setFrameOpen(false)}
              className="mt-2 inline-flex items-center gap-1.5 text-[11px] font-semibold tracking-wider text-dim transition hover:text-tox"
            >
              <X className="h-3.5 w-3.5" />
              HIDE FRAME
            </button>
          </div>
        )}
        <p className="mt-2 text-[10px] leading-relaxed text-dim">
          The frame loads with scripts, forms, popups and storage fully disabled. Sites sending
          anti-framing headers will refuse to render — that refusal is normal and expected.
        </p>
      </div>
    </section>
  );
}
