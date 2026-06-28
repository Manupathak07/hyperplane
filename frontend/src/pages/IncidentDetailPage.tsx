import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock, Server } from "lucide-react";

import { api } from "@/lib/api";
import SeverityBadge from "@/components/incidents/SeverityBadge";
import DomainBadge from "@/components/incidents/DomainBadge";
import { formatDateTime, formatRelative } from "@/lib/utils";

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["incident", id],
    queryFn: () => api.getIncident(id!),
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div className="mx-auto max-w-5xl text-sm text-muted-foreground">
        Loading incident…
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="mx-auto max-w-5xl space-y-3">
        <Link
          to="/incidents"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3 w-3" /> Back to incidents
        </Link>
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          Could not load incident: {(error as Error).message}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <Link
        to="/incidents"
        className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3 w-3" /> Back to incidents
      </Link>

      <div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge value={data.severity} />
          <DomainBadge value={data.domain} />
          <span className="rounded bg-muted px-2 py-0.5 text-xs uppercase tracking-wide text-muted-foreground">
            {data.status}
          </span>
          <span className="font-mono text-xs text-muted-foreground">
            {data.source}
          </span>
        </div>
        <h2 className="mt-3 text-xl font-semibold">{data.title}</h2>
        {data.description && (
          <p className="mt-1 text-sm text-muted-foreground">{data.description}</p>
        )}
        <div className="mt-3 flex items-center gap-4 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {formatRelative(data.created_at)} · {formatDateTime(data.created_at)}
          </span>
        </div>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Raw event
        </h3>
        <pre className="overflow-auto rounded-md border border-border bg-card p-4 text-xs leading-relaxed">
          {JSON.stringify(data.raw_event, null, 2)}
        </pre>
      </div>

      <div className="rounded-md border border-dashed border-border bg-card/40 p-6 text-center">
        <Server className="mx-auto h-6 w-6 text-muted-foreground" />
        <div className="mt-2 text-sm font-medium">Agent Trace Viewer</div>
        <p className="mt-1 text-xs text-muted-foreground">
          Will render the full 6-agent trace here (input, output, reasoning, duration).
          <br />
          Available in <span className="font-mono">Week 11</span> once all agents are wired up.
        </p>
      </div>
    </div>
  );
}