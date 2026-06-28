import { Link } from "react-router-dom";
import { Activity } from "lucide-react";

import { useRecentEvents } from "@/hooks/useRecentEvents";
import { cn, formatRelative } from "@/lib/utils";

const DOMAIN_DOT: Record<string, string> = {
  IT: "bg-cyan-400",
  OT: "bg-violet-400",
  IoT: "bg-pink-400",
};

const SEV_DOT: Record<string, string> = {
  low: "bg-emerald-400",
  medium: "bg-amber-400",
  high: "bg-orange-400",
  critical: "bg-red-400",
};

export default function RecentEventsTimeline({ limit = 6 }: { limit?: number }) {
  const { data, isLoading } = useRecentEvents(limit);

  return (
    <div>
      <div className="mb-3 flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
        <Activity className="h-3 w-3" />
        Recent events
      </div>
      {isLoading && (
        <div className="text-xs text-muted-foreground">Loading…</div>
      )}
      {data && data.length === 0 && (
        <div className="text-xs text-muted-foreground">No events yet.</div>
      )}
      {data && data.length > 0 && (
        <ol className="relative space-y-2 border-l border-border/60 pl-4">
          {data.map((inc) => (
            <li key={inc.id} className="relative">
              <span
                className={cn(
                  "absolute -left-[1.42rem] top-1.5 h-2 w-2 rounded-full ring-4 ring-card",
                  DOMAIN_DOT[inc.domain] ?? "bg-muted-foreground",
                )}
              />
              <Link
                to={`/incidents/${inc.id}`}
                className="block rounded px-2 py-1.5 -mx-2 transition-colors hover:bg-accent/50"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs font-medium text-foreground">
                    {inc.title}
                  </span>
                  <span
                    className={cn(
                      "h-1.5 w-1.5 shrink-0 rounded-full",
                      SEV_DOT[inc.severity] ?? "bg-muted-foreground",
                    )}
                    title={inc.severity}
                  />
                </div>
                <div className="mt-0.5 flex items-center gap-2 text-[10px] text-muted-foreground">
                  <span className="font-mono">{inc.domain}</span>
                  <span>·</span>
                  <span>{formatRelative(inc.created_at)}</span>
                </div>
              </Link>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}