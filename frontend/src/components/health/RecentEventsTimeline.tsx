import { Link } from "react-router-dom";
import { Activity } from "lucide-react";

import { useRecentEvents } from "@/hooks/useRecentEvents";
import { cn, formatRelative } from "@/lib/utils";

const DOMAIN_DOT: Record<string, string> = {
  IT: "hp-live",
  OT: "dom-ot",
  IoT: "dom-iot",
};

const SEV_DOT: Record<string, string> = {
  low: "hp-healthy",
  medium: "hp-warning",
  high: "hp-warning",
  critical: "hp-critical",
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
        <ol className="relative space-y-2 border-l pl-4" style={{ borderColor: "#243042" }}>
          {data.map((inc) => (
            <li key={inc.id} className="relative">
              <span
                className={cn(
                  "absolute -left-[1.42rem] top-1.5 h-2 w-2 rounded-full ring-4",
                  DOMAIN_DOT[inc.domain] ?? "bg-muted-foreground",
                )}
                style={{ backgroundColor:
                  inc.domain === "IT" ? "#3BC7FF" :
                  inc.domain === "OT" ? "#B8B0FF" :
                  inc.domain === "IoT" ? "#9AA7B2" : "#5B6B7A"
                }}
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
                    className="h-1.5 w-1.5 shrink-0 rounded-full"
                    title={inc.severity}
                    style={{ backgroundColor:
                      inc.severity === "low" ? "#2EE59D" :
                      inc.severity === "medium" ? "#FFB020" :
                      inc.severity === "high" ? "#FFB020" :
                      inc.severity === "critical" ? "#FF4D4F" : "#5B6B7A"
                    }}
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