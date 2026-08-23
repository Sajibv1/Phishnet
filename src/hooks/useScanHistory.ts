import { useCallback, useState } from "react";
import type { ScanResult } from "@/lib/phishingEngine";

const STORAGE_KEY = "phishguard.history.v1";
const MAX_ITEMS = 12;

function load(): ScanResult[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as ScanResult[];
    return Array.isArray(parsed) ? parsed.slice(0, MAX_ITEMS) : [];
  } catch {
    return [];
  }
}

export function useScanHistory() {
  const [items, setItems] = useState<ScanResult[]>(load);

  const persist = useCallback((next: ScanResult[]) => {
    setItems(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // storage unavailable (private mode etc.) — keep in-memory only
    }
  }, []);

  const add = useCallback(
    (result: ScanResult) => {
      const existing = load().filter((x) => x.href !== result.href);
      persist([result, ...existing].slice(0, MAX_ITEMS));
    },
    [persist],
  );

  const clear = useCallback(() => persist([]), [persist]);

  return { items, add, clear };
}
