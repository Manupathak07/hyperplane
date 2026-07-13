import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock, Server } from "lucide-react";

import { api } from "@/lib/api";
import { useTraceStream } from "@/lib/api";
import SeverityBadge from "@/components/incidents/SeverityBadge";
import DomainBadge from "@/components/incidents/DomainBadge";
import { formatDateTime, formatRelative } from "@/lib/utils";

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<any>(null);
  const [traces, setTraces] = useState<Array<any>>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Fetch initial data
  useEffect(() => {
    loadInitialData();
  }, [id]);

  // WebSocket connection for real-time trace updates
  useTraceStream(
    id,
    (newTrace) => {
      setTraces((prev) => {
        // Check if trace already exists (by id)
        const existingIndex = prev.findIndex((t) => t.id === newTrace.id);
        if (existingIndex >= 0) {
          // Update existing trace
          const updated = [...prev];
          updated[existingIndex] = newTrace;
          return updated;
        } else {
          // Add new trace, keeping them sorted by step
          return [...prev, newTrace].sort((a, b) => a.step - b.step);
        }
      });
    }
  );

  const loadInitialData = async () => {
    try {
      setIsLoading(true);
      const data = await api.getIncident(id!);
      setIncident(data);
      setTraces(data.traces || []); // Initialize traces from initial data
      setIsError(false);
    } catch (err) {
      setIsError(true);
      setError(err instanceof Error ? err : new Error(String(err)));
      console.error(`Failed to load incident ${id}:`, err);
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
        Loading incident…
      </div>
    );
  }

  if (isError || !incident) {
    return (
      <div className="mx-auto max-w-5xl space-y-3">
        <div className="p-4 bg-red-50 rounded-lg border border-red-200">
          <div className="flex items-start gap-3">
            <ArrowLeft className="h-5 w-5 text-red-400 flex-shrink-0" />
            <div>
              <p className="font-medium text-red-800">Error loading incident</p>
              <p className="text-sm text-red-600">{error?.message}</p>
            </div>
          </div>
        </div>
        <div className="flex justify-between">
          <Link to="/incidents">
            <button className="btn btn-outline">← Back to incidents</button>
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
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ── HEADER ────────────────────────────────────────────────── */}
      <div className="flex justify-between items-start">
        <div className="flex items-center space-x-4">
          <Link to="/incidents">
            <button className="btn btn-ghost">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to incidents
            </button>
          </Link>
          <div className="space-y-1">
            <h1 className="text-xl font-semibold">{incident.title}</h1>
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge 
                variant={incident.severity === "critical" ? "destructive" : 
                         incident.severity === "high" ? "warning" : 
                         incident.severity === "medium" ? "secondary" : "default"}
              >
                {incident.severity.toUpperCase()}
              </Badge>
              <Badge variant="secondary">{incident.domain}</Badge>
              <Badge 
                variant={incident.status === "new" ? "default" :
                         incident.status === "contained" ? "success" :
                         incident.status === "investigating" ? "warning" : "secondary"}
              >
                {incident.status.toUpperCase()}
              </Badge>
              {incident.correlation_id && (
                <Badge variant="outline">{incident.correlation_id.slice(0, 8)}...</Badge>
              )}
            </div>
          </div>
        </div>
        <div className="text-right text-sm text-muted-foreground">
          <p className="mb-1">{formatRelative(incident.created_at)}</p>
          <p className="text-xs">Live trace updates enabled</p>
        </div>
      </div>

      {/* ── INCIDENT DETAILS ──────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Panel title="Event Info">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="font-medium">Event Type:</span>
              <span className="font-mono">{incident.event_type ?? "—"}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-medium">Source:</span>
              <span className="badge-outline">{incident.source}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-medium">Correlation ID:</span>
              <span className="font-mono">
                {incident.correlation_id ?? "—"}
              </span>
            </div>
          </div>
        </div>

        <Panel title="Threat Intelligence">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="font-medium">Score:</span>
              <span className="font-mono">
                {(incident.threat_intel?.score ?? 0).toFixed(1)} / 100
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-medium">Sources:</span>
              <span className="font-mono">
                {((incident.threat_intel?.hits || []) as any[]).map((h: any) => h.source).join(", ") || "None"}
              </span>
            </div>
          </div>
        </div>

        <Panel title="Detection Results">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="font-medium">Score:</span>
              <span className="font-mono">
                {incident.detection_score?.toFixed(1) ?? "0"} / 100
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-medium">Attack Stage:</span>
              <span className="font-mono italic">
                {incident.attack_stage ?? "—"}
              </span>
            </div>
            <div className="flex items-wrap gap-2">
              <span className="font-medium">Related Incidents:</span>
              <span className="font-mono">
                {incident.related_incident_ids.length > 0
                  ? `${incident.related_incident_ids.length} linked`
                  : "None"}
              </span>
            </div>
          </div>
        </div>

        <Panel title="Response Actions">
          <div className="space-y-2">
            {(incident.response?.recommended_actions || [] as string[]).map((action, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <div className="flex-shrink-0">
                  <Circle className="h-3 w-3 bg-green-500" />
                </div>
                <div>{action}</div>
              </div>
            ))}
            {!incident.response?.recommended_actions?.length && (
              <p className="text-muted-foreground">No specific actions recommended</p>
            )}
          </div>
        </div>
      </div>

      {/* ── TIMELINE & TRACE VIEWER ─────────────────────────────── */}
      <div className="grid gap-4">
        <div className="col-span-1">
          <SectionTitle>
            Investigation Timeline
            <div className="text-xs text-muted-foreground ml-4">
              Real-time agent trace updates
            </div>
          </div>
          <div className="space-y-3">
            {traces.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                Waiting for agent traces…
              </div>
            ) : (
              <div className="space-y-2">
                {traces.map((trace) => (
                  <TraceCard key={trace.id} trace={trace} />
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="col-span-1">
          <SectionTitle>
            Incident Overview
            <div className="text-xs text-muted-foreground ml-4">
              Summary of key findings
            </div>
          </div>
          <div className="space-y-4">
            <div className="border rounded-lg p-4">
              <div className="space-y-3">
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0">
                    <Circle className="h-4 w-4 bg-blue-500" />
                  </div>
                  <div>
                    <p className="font-medium">Event processed through 6-agent pipeline</p>
                    <p className="text-sm text-muted-foreground">
                      {incident.event_type} incident from {incident.source}
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0">
                    {incident.severity === "critical" ? (
                      <Circle className="h-4 w-4 bg-red-500" />
                    ) : incident.severity === "high" ? (
                      <Circle className="h-4 w-4 bg-orange-500" />
                    ) : (
                      <Circle className="h-4 w-4 bg-yellow-500" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium">Threat level: {incident.severity.toUpperCase()}</p>
                    <p className="text-sm text-muted-foreground">
                      Score: {(incident.threat_intel?.score ?? 0).toFixed(0)}/100
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0">
                    <Check className="h-4 w-4" 
                           status={incident.status === "contained" || incident.status === "closed" ? "complete" : "in-progress"} />
                  </div>
                  <div>
                    <p className="font-medium">Response status: {incident.status.toUpperCase()}</p>
                    <p className="text-sm text-muted-foreground">
                      {incident.response?.recommended_actions?.length ?? 0} actions recommended
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------- COMPONENTS ---------- */

function SectionTitle(
  children: React.ReactNode,
  { className = "" } = {}
) {
  return (
    <div className={`mb-4 flex w-full items-center gap-2 ${className}`}>
      <h2 className="text-lg font-semibold">{children}</h2>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border rounded-lg">
      <div className="px-4 py-3 text-sm font-medium border-b">{title}</div>
      <div className="px-4 py-4">{children}</div>
    </div>
  );
}

function TraceCard({ trace }: { trace: any }) {
  const statusColors: Record<string, string> = {
    success: "bg-green-50 text-green-600",
    failed: "bg-red-50 text-red-600",
    skipped: "bg-gray-50 text-gray-600",
  };

  return (
    <div className="border rounded-lg p-4">
      <div className="flex items-start gap-3 mb-2">
        <div className="flex-shrink-0">
          <div className={`w-2 h-2 rounded-full bg-blue-500`} />
        </div>
        <div className="flex-1 space-y-1">
          <div className="flex justify-between text-xs font-medium">
            <span>
              Step {trace.step}: {trace.agent_name.replace("_", " ").toUpperCase()}
            </span>
            <span className={`px-2 px-1.5 rounded text-xs ${statusColors[trace.status]}`}>
              {trace.status}
            </span>
          </div>
          <div className="text-sm">{trace.reasoning || "No reasoning provided"}</div>
          {trace.duration_ms !== null && (
            <div className="text-xs text-muted-foreground">
              ⏱️ {trace.duration_ms}ms
            </div>
          )}
        </div>
      </div>
      <div className="mt-3 pt-2 border-t border-muted">
        <div className="text-xs font-semibold mb-1">Input</div>
        <pre className="text-xs bg-muted p-3 rounded overflow-x-auto">
          {JSON.stringify(trace.input, null, 2)}
        </pre>
        <div className="mt-3 pt-2 border-t border-muted">
          <div className="text-xs font-semibold mb-1">Output</div>
          <pre className="text-xs bg-muted p-3 rounded overflow-x-auto">
            {JSON.stringify(trace.output, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}
