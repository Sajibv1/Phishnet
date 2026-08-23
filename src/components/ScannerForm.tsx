import { useState, type FormEvent } from "react";
import { AlertTriangle, Globe, Loader2, Zap } from "lucide-react";

interface Props {
  scanning: boolean;
  error: string | null;
  onScan: (url: string) => void;
}

export default function ScannerForm({ scanning, error, onScan }: Props) {
  const [value, setValue] = useState("");

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!scanning) onScan(value);
  };

  return (
    <div>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Globe className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-dim" />
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={scanning}
            spellCheck={false}
            autoComplete="off"
            inputMode="url"
            placeholder="paste a suspicious link… e.g. http://secure-paypal.verify.tk/login"
            aria-label="URL to scan"
            className={`w-full rounded-lg border bg-[#070d10] py-3.5 pl-11 pr-4 text-sm text-fog outline-none transition placeholder:text-dim/60 disabled:opacity-60 ${
              error
                ? "border-tox/60"
                : "border-edge focus:border-neon/60 focus:shadow-[0_0_0_3px_rgba(0,255,156,0.08)]"
            }`}
          />
        </div>
        <button
          type="submit"
          disabled={scanning}
          className="glow-neon inline-flex items-center justify-center gap-2 rounded-lg bg-neon px-6 py-3.5 text-xs font-extrabold tracking-[0.18em] text-void transition hover:bg-[#33ffb5] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-70"
        >
          {scanning ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              SCANNING…
            </>
          ) : (
            <>
              <Zap className="h-4 w-4" />
              RUN SCAN
            </>
          )}
        </button>
      </form>
      {error && (
        <p className="mt-2.5 flex items-center gap-1.5 text-xs text-tox">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          {error}
        </p>
      )}
    </div>
  );
}
