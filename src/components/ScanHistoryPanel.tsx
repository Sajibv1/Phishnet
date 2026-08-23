import { ChevronRight, Trash2 } from "lucide-react";
import { VERDICT_META, type ScanResult } from "@/lib/phishingEngine";

function timeAgo(ts: number): string {
  const seconds = Math.floor((Date.now() - ts) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

interface Props {
  items: ScanResult[];
  onSelect: (result: ScanResult) => void;
  onClear: () => void;
}

export default function ScanHistoryPanel({ items, onSelect, onClear }: Props) {
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-edge bg-panel/50 p-8 text-center">
        <p className="text-xs leading-relaxed text-dim">
          No scans yet. Your last 12 results are kept locally on this device.
        </p>
      </div>
    );
  }

  return (
    <div>
      <ul className="space-y-2.5">
        {items.map((item) => {
          const color = VERDICT_META[item.verdict].color;
          return (
            <li key={item.id}>
              <button
                onClick={() => onSelect(item)}
                className="group flex w-full items-center gap-3.5 rounded-xl border border-edge bg-panel px-4 py-3 text-left transition hover:border-neon/40 hover:bg-raise"
              >
                <span
                  className="h-8 w-1 shrink-0 rounded-full"
                  style={{ backgroundColor: color }}
                  aria-hidden
                />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-semibold text-fog">{item.host}</span>
                  <span className="block truncate text-[11px] text-dim">
                    {item.inputUrl} · {timeAgo(item.scannedAt)}
                  </span>
                </span>
                <span
                  className="shrink-0 rounded-md px-2 py-1 text-[11px] font-extrabold tabular-nums"
                  style={{ backgroundColor: `${color}1a`, color }}
                >
                  {item.riskScore}
                </span>
                <ChevronRight className="h-4 w-4 shrink-0 text-dim transition group-hover:translate-x-0.5 group-hover:text-neon" />
              </button>
            </li>
          );
        })}
      </ul>
      <button
        onClick={onClear}
        className="mt-3 inline-flex items-center gap-1.5 text-[11px] font-semibold tracking-wider text-dim transition hover:text-tox"
      >
        <Trash2 className="h-3.5 w-3.5" />
        CLEAR HISTORY
      </button>
    </div>
  );
}
