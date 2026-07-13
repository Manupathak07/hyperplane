import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, RefreshCw } from "lucide-react";

import { api } from "@/lib/api";
import { useEventStream } from "@/lib/api";
import SeverityBadge from "@/components/incidents/SeverityBadge";
import DomainBadge from "@/components/incidents/DomainBadge";
import CorrelationBadge from "@/components/incidents/CorrelationBadge";
import { formatDateTime, formatRelative } from "@/lib/utils";

type Counts = {
  total: number;
  critical: number;
  high: number;
  new: number;
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Array<any>>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [counts, setCounts] = useState({
    total: 0,
    critical: 0,
    high: 0,
    new: 0,
  });

  // Fetch initial data
  useEffect(() => {
    loadInitialData();
  }, []);

  // WebSocket connection for real-time updates
  useEventStream((newEvent) => {
    setIncidents((prev) => {
      // Check if event already exists
      const existingIndex = prev.findIndex(
        (inc) => inc.id === newEvent.id
      );
      
      if (existingIndex >= 0) {
        // Update existing incident
        const updated = [...prev];
        updated[existingIndex] = newEvent;
        return updated;
      } else {
        // Add new incident to the beginning (most recent first)
        return [newEvent, ...prev];
      }
    });
  });

  const loadInitialData = async () => {
    try {
      setIsLoading(true);
      const data = await api.listIncidents(200);
      setIncidents(data);
      setIsError(false);
      
      // Calculate counts
      const counts: Counts = data.reduce(
        (acc, inc) => {
          acc.total++;
          if (inc.severity === "critical") acc.critical++;
          if (inc.severity === "high") acc.high++;
          if (inc.status === "new") acc.new++;
          return acc;
        },
        { total: 0, critical: 0, high: 0, new: 0 }
      );
      setCounts(counts);
    } catch (err) {
      setIsError(true);
      setError(err instanceof Error ? err : new Error(String(err)));
      console.error("Failed to load incidents:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRefresh = async () => {
    await loadInitialData();
  };

  if (isLoading) {
    return (
      <div className="mx-auto max-w-5xl text-sm text-muted-foreground">
        Loading incidents…
      </div>
    );
  }

  if (isError) {
    return (
      <div className="mx-auto max-w-5xl space-y-3">
        <div className="p-4 bg-red-50 rounded-lg border border-red-200">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0" />
            <div>
              <p className="font-medium text-red-800">Error loading incidents</p>
              <p className="text-sm text-red-600">{error?.message}</p>
            </div>
          </div>
        </div>
        <div className="flex justify-end">
          <button
            onClick={handleRefresh}
            className="btn btn-sm btn-outline"
          >
            <RefreshCw className="mr-2 h-4 w-4" /> Retry
          </button>
        </div>
      </div>
    );
  }

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
        <Stat label="New" value={counts.new} tone="info" />
      </div>

      {/* ── SECONDARY: incident table ─────────────────────────────── */}
      <div className="border rounded-lg">
        <div className="border-b bg-muted px-4 py-3 text-sm font-medium">
          Recent Incidents
          <div className="ml-auto text-xs text-muted-foreground">
            Live updates enabled
          </div>
        </div>
        <div className="overflow-y-auto max-h-[400px]">
          <table className="w-full text-sm">
            <thead className="bg-muted">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Time
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Source
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Details
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {incidents.length === 0 ? (
                <tr>
                  <td colspan="6" className="px-4 py-4 text-center text-muted-foreground">
                    No incidents found
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    className="transition-colors hover:bg-accent/40"
                  >
                    <td className="px-4 py-3 text-sm font-mono">
                      {formatRelative(inc.created_at)}
                    </td>
                    <td className="px-4 py-3 text-xs">{inc.event_type ?? "—"}</td>
                    <td className="px-4 py-3">
                      <span className="badge-outline">{inc.source}</span>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge value={inc.severity} numeric={inc.severity_numeric} />
                    </td>
                    <td className="px-4 py-3 text-xs">
                      <span className={`badge-outline ${getStatusVariant(inc.status)}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs">
                      <div className="flex flex-col gap-1">
                        {inc.correlation_id && (
                          <span className="flex items-center gap-1 text-xs">
                            <CorrelationBadge value={inc.correlation_id} />
                          </span>
                        )}
                        {inc.description && (
                          <span className="line-clamp-1">{inc.description}</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <div className="border-t px-4 py-3 text-xs text-muted-foreground flex justify-between">
          <span>Last updated: just now</span>
          <button onClick={handleRefresh} className="btn btn-xs btn-outline">
            <RefreshCw className="mr-1 h-3 w-3" /> Refresh
          </button>
        </div>
      </div>
    </div>
  );
}

function getStatusVariant(status: string): string {
  switch (status) {
    case "new":
      return "bg-blue-50 text-blue-600";
    case "triaging":
      return "bg-yellow-50 text-yellow-600";
    case "investigating":
      return "bg-purple-50 text-purple-600";
    case "contained":
      return "bg-green-50 text-green-600";
    case "closed":
      return "bg-gray-50 text-gray-600";
    default:
      return "bg-gray-50 text-gray-600";
  }
}
