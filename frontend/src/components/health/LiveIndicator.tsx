import { useEffect, useState } from "react";
import { RefreshCw, Radio } from "lucide-react";

import { useLatencyTracker } from "@/hooks/useLatencyTracker";
import { cn, formatRelative } from "@/lib/utils";

interface Props {
  intervalMs?: number;
}

/**
 * Live system indicator: pulse dot + last-updated + heartbeat animation.
 * Sits next to the HealthPill in the Header so the user always sees the
 * system is "breathing".
 */
export default function LiveIndicator({ intervalMs = 30_000 }: Props) {
  const { last } = useLatencyTracker(intervalMs / 6); // sample 6x more often than the pill refresh
  const [now, setNow] = useState(Date.now());

  // re-render once a second so the "Xs ago" stays fresh
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
            recent ? "bg-emerald-400 animate-ping" : "bg-muted-foreground/40",
          )}
        />
        <span
          className={cn(
            "relative inline-flex h-2 w-2 rounded-full",
            recent ? "bg-emerald-400" : "bg-muted-foreground/40",
          )}
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