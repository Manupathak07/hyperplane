import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { AlertTriangle, RefreshCw } from "lucide-react";

import { api } from "@/lib/api";
import SeverityBadge from "@/components/incidents/SeverityBadge";
import DomainBadge from "@/components/incidents/DomainBadge";
import { formatDateTime, formatRelative } from "@/lib/utils";

type Counts = {
  total: number;
  critical: number;
  high: number;
  new: number;
};

export default function IncidentsPage() {
  const { data, isLoading, isError, error, refetch, isRefetching } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => api.listIncidents(50),
    refetchInterval: 15_000,
  });

  const counts: Counts = (data ?? []).reduce(
    (acc, inc) => {
      acc.total++;
      if (inc.severity === "critical") acc.critical++;
      if (inc.severity === "high") acc.high++;
      if (inc.status === "new") acc.new++;
      return acc;
    },
    { total: 0, critical: 0, high: 0, new: 0 },
  );

  return (
    <div className="space-y-4">
      {/* ── PRIMARY: stat row ─────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Total" value={counts.total} tone="neutral" />
        <Stat
          label="Critical"
          value={counts.critical}
          tone={counts.critical > 0 ? "bad" : "muted"}
        />
        <Stat
          label="High"
          value={counts.high}
          tone={counts.high > 0 ? "warn" : "muted"}
        />
        <Stat
          label="New"
          value={counts.new}
          tone={counts.new > 0 ? "ok" : "muted"}
        />
      </div>

      {/* ── SECONDARY: table card ─────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {data
            ? `${data.length} incident${data.length === 1 ? "" : "s"} on record`
            : "Loading…"}
        </div>
        <button
          type="button"
          onClick={() => refetch()}
          disabled={isRefetching}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${isRefetching ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {isLoading && (
        <div className="rounded-md border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          Loading incidents…
        </div>
      )}

      {isError && (
        <div className="rounded-md border p-4 text-sm hp-critical hp-critical-bg">
          Could not load incidents: {(error as Error).message}
        </div>
      )}

      {data && data.length === 0 && (
        <div className="rounded-md border border-dashed border-border bg-card/50 p-12 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-muted-foreground" />
          <div className="mt-3 text-sm font-medium">No incidents yet</div>
          <p className="mt-1 text-xs text-muted-foreground">
            Run the seed script to add an example:
            <code className="ml-1 rounded bg-muted px-1.5 py-0.5 text-[10px]">
              docker exec hyperplane-backend python -m scripts.seed
            </code>
          </p>
        </div>
      )}

      {data && data.length > 0 && (
        <div className="overflow-hidden rounded-md border border-border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-background/50 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Title</th>
                <th className="px-4 py-2 text-left font-medium">Severity</th>
                <th className="px-4 py-2 text-left font-medium">Domain</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                <th className="px-4 py-2 text-left font-medium">Source</th>
                <th className="px-4 py-2 text-right font-medium">Detected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data.map((inc) => (
                <tr
                  key={inc.id}
                  className="transition-colors hover:bg-accent/40"
                >
                  <td className="px-4 py-3">
                    <Link
                      to={`/incidents/${inc.id}`}
                      className="font-medium text-foreground hover:text-primary"
                    >
                      {inc.title}
                    </Link>
                    {inc.description && (
                      <div className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">
                        {inc.description}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge value={inc.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <DomainBadge value={inc.domain} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-muted px-2 py-0.5 text-xs uppercase tracking-wide text-muted-foreground">
                      {inc.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                    {inc.source}
                  </td>
                  <td
                    className="px-4 py-3 text-right text-xs text-muted-foreground"
                    title={formatDateTime(inc.created_at)}
                  >
                    {formatRelative(inc.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "ok" | "warn" | "bad" | "muted" | "neutral";
}) {
  const valueClass =
    tone === "ok"
      ? "hp-healthy"
      : tone === "warn"
        ? "hp-warning"
        : tone === "bad"
          ? "hp-critical"
          : tone === "neutral"
            ? "text-foreground"
            : "text-muted-foreground";
  return (
    <div className="rounded-md border border-border bg-card p-4">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${valueClass}`}>
        {value}
      </div>
    </div>
  );
}