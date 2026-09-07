import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock, Server, RefreshCw, Circle, Check } from "lucide-react";

import { api, useTraceStream } from "@/lib/api";
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

  useEffect(() => {
    loadInitialData();
  }, [id]);

  useTraceStream(
    id,
    (newTrace) => {
      setTraces((prev) => {
        const existingIndex = prev.findIndex((t) => t.id === newTrace.id);
        if (existingIndex >= 0) {
          const updated = [...prev];
          updated[existingIndex] = newTrace;
          return updated;
        } else {
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
      setTraces(data.traces || []);
      setIsError(false);
    } catch (err) {
      setIsError(true);
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  };

  const handleRefresh = async () => {
    await loadInitialData();
  };

  if (isLoading) {
    return <div className="mx-auto max-w-5xl text-sm text-muted-foreground">Loading incident…</div>;
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
          </Link>
          <button onClick={handleRefresh} className="btn btn-sm btn-outline">
            <RefreshCw className="mr-2 h-4 w-4" /> Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
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
              <SeverityBadge severity={incident.severity} />
              <DomainBadge domain={incident.domain} />
              <div className="px-2 py-0.5 rounded bg-secondary text-secondary-foreground">
                {incident.status?.toUpperCase()}
              </div>
            </div>
          </div>
        </div>
        <div className="text-right text-sm text-muted-foreground">
          <p className="mb-1">{formatRelative(incident.created_at)}</p>
          <p className="text-xs">Live trace updates enabled</p>
        </div>
      </div>

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
          </div>
        </Panel>

        <Panel title="Threat Intelligence">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="font-medium">Score:</span>
              <span className="font-mono">{(incident.threat_intel?.score ?? 0).toFixed(1)}/100</span>
            </div>
          </div>
        </Panel>

        <Panel title="Detection Results">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="font-medium">Score:</span>
              <span className="font-mono">{incident.detection_score?.toFixed(1) ?? "0"}/100</span>
            </div>
          </div>
        </Panel>

        <Panel title="Response Actions">
          <div className="space-y-2">
            {(incident.response?.recommended_actions || []).map((action: string, idx: number) => (
              <div key={idx} className="flex items-start gap-2">
                <Circle className="h-3 w-3 fill-green-500 text-green-500" />
                <div>{action}</div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid gap-4">
        <SectionTitle>Investigation Timeline</SectionTitle>
        <div className="space-y-3">
          {traces.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">Waiting for agent traces…</div>
          ) : (
            traces.map((trace) => <TraceCard key={trace.id} trace={trace} />)
          )}
        </div>
      </div>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <div className="mb-4 flex w-full items-center gap-2"><h2 className="text-lg font-semibold">{children}</h2></div>;
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
  const statusColors: any = { success: "bg-green-50 text-green-600", failed: "bg-red-50 text-red-600", skipped: "bg-gray-50 text-gray-600" };
  return (
    <div className="border rounded-lg p-4">
      <div className="flex items-start gap-3 mb-2">
        <div className="w-2 h-2 rounded-full bg-blue-500" />
        <div className="flex-1 space-y-1">
          <div className="flex justify-between text-xs font-medium">
            <span>Step {trace.step}: {trace.agent_name?.toUpperCase()}</span>
            <span className={`px-2 py-0.5 rounded text-xs ${statusColors[trace.status] || "bg-gray-50"}`}>{trace.status}</span>
          </div>
          <div className="text-sm">{trace.reasoning}</div>
        </div>
      </div>
    </div>
  );
}
