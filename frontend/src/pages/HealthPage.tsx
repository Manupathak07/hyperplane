import { useQuery } from "@tanstack/react-query";
import { Activity, Database, Server } from "lucide-react";

import { api } from "@/lib/api";
import SeverityBadge from "@/components/incidents/SeverityBadge";
import DomainBadge from "@/components/incidents/DomainBadge";
import { formatDateTime } from "@/lib/utils";

export default function HealthPage() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 15_000,
  });

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Backend
        </h2>
        {isLoading && <StatusCard state="loading" />}
        {isError && (
          <StatusCard
            state="error"
            message={(error as Error).message}
            onRetry={() => refetch()}
          />
        )}
        {data && (
          <div className="grid gap-4 md:grid-cols-3">
            <MetricCard
              icon={Activity}
              label="API"
              value={data.status === "ok" ? "operational" : "degraded"}
              tone={data.status === "ok" ? "ok" : "warn"}
            />
            <MetricCard
              icon={Database}
              label="Database"
              value={data.database === "up" ? "connected" : "down"}
              tone={data.database === "up" ? "ok" : "bad"}
            />
            <MetricCard
              icon={Server}
              label="Service"
              value={data.service}
              tone="neutral"
            />
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Raw response
        </h2>
        <pre className="overflow-auto rounded-md border border-border bg-card p-4 text-xs leading-relaxed">
          {JSON.stringify(data ?? { loading: true }, null, 2)}
        </pre>
      </section>

      {data && data.status === "ok" && (
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Quick reference
          </h2>
          <div className="grid gap-3 text-sm md:grid-cols-2">
            <div className="rounded-md border border-border bg-card p-4">
              <div className="text-xs uppercase tracking-wider text-muted-foreground">
                Next check
              </div>
              <div className="mt-1 font-mono">
                {formatDateTime(new Date(Date.now() + 15_000).toISOString())}
              </div>
            </div>
            <div className="rounded-md border border-border bg-card p-4">
              <div className="text-xs uppercase tracking-wider text-muted-foreground">
                Severity legend
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <SeverityBadge value="low" />
                <SeverityBadge value="medium" />
                <SeverityBadge value="high" />
                <SeverityBadge value="critical" />
                <span className="mx-1 text-muted-foreground">·</span>
                <DomainBadge value="IT" />
                <DomainBadge value="OT" />
                <DomainBadge value="IoT" />
              </div>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  tone: "ok" | "warn" | "bad" | "neutral";
}) {
  const toneClass =
    tone === "ok"
      ? "text-emerald-300 bg-emerald-500/15"
      : tone === "warn"
        ? "text-amber-300 bg-amber-500/15"
        : tone === "bad"
          ? "text-red-300 bg-red-500/15"
          : "text-cyan-300 bg-cyan-500/15";
  return (
    <div className="rounded-md border border-border bg-card p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div
        className={`mt-2 inline-flex items-center rounded-md px-2 py-0.5 text-sm font-medium ${toneClass}`}
      >
        {value}
      </div>
    </div>
  );
}

function StatusCard({
  state,
  message,
  onRetry,
}: {
  state: "loading" | "error";
  message?: string;
  onRetry?: () => void;
}) {
  if (state === "loading") {
    return (
      <div className="rounded-md border border-border bg-card p-4 text-sm text-muted-foreground">
        Checking backend…
      </div>
    );
  }
  return (
    <div className="rounded-md border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
      <div className="font-medium">Backend unreachable</div>
      <div className="mt-1 text-xs text-red-300/80">{message}</div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded-md border border-red-500/40 px-2 py-1 text-xs hover:bg-red-500/15"
        >
          Retry
        </button>
      )}
    </div>
  );
}