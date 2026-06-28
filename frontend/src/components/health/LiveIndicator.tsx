import { useEffect, useState } from "react";
import { RefreshCw, Radio } from "lucide-react";

import { useLatencyTracker } from "@/hooks/useLatencyTracker";
import { cn, formatRelative } from "@/lib/utils";

interface Props {
  intervalMs?: number;
}

/**
 * Live system indicator: cyan pulse dot + last-updated + heartbeat.
 * Per the colour rules, this uses --hp-live (cyan) — cyan is reserved for
 * live/telemetry only.
 */
export default function LiveIndicator({ intervalMs = 30_000 }: Props) {
  const { last } = useLatencyTracker(intervalMs / 6);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(t);
  }, []);

  const recent = last !== null && now - last.t < intervalMs * 2;

  return (
    <div
      className={cn(
        "hidden items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground md:flex",
        !recent && "opacity-60",
      )}
      title={`Auto-refresh every ${Math.round(intervalMs / 1000)}s`}
    >
      <span className="relative flex h-2 w-2">
        <span
          className={cn(
            "absolute inline-flex h-full w-full rounded-full opacity-75",
            recent ? "animate-ping" : "",
          )}
          style={{ backgroundColor: recent ? "#3BC7FF" : "#5B6B7A" }}
        />
        <span
          className="relative inline-flex h-2 w-2 rounded-full"
          style={{ backgroundColor: recent ? "#3BC7FF" : "#5B6B7A" }}
        />
      </span>
      <Radio className="h-3 w-3" />
      <span>
        live ·{" "}
        {last ? formatRelative(new Date(last.t).toISOString()) : "—"}
      </span>
      <RefreshCw className="h-3 w-3 opacity-50" />
    </div>
  );
}