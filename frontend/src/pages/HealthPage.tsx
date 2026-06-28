import { useQuery } from "@tanstack/react-query";
import { Activity, Database, Server } from "lucide-react";

import { api } from "@/lib/api";
import SeverityBadge from "@/components/incidents/SeverityBadge";
import DomainBadge from "@/components/incidents/DomainBadge";
import { AccordionItem } from "@/components/ui/accordion";
import { formatDateTime } from "@/lib/utils";

export default function HealthPage() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 15_000,
  });

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* ── PRIMARY: status banner with subtle violet signature glow ── */}
      {isLoading && <Banner tone="muted">Checking backend…</Banner>}
      {isError && (
        <Banner tone="bad">
          <div className="font-medium">Backend unreachable</div>
          <div className="mt-1 text-xs opacity-80">{(error as Error).message}</div>
          <button
            type="button"
            onClick={() => refetch()}
            className="mt-3 rounded-md border px-2 py-1 text-xs hover:bg-red-500/15 hp-critical-bg"
          >
            Retry
          </button>
        </Banner>
      )}
      {data && (
        <Banner tone={data.status === "ok" ? "ok" : "warn"}>
          <div className="flex items-center gap-3">
            <span className="relative flex h-3 w-3">
              <span
                className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75"
                style={{ backgroundColor: "#2EE59D" }}
              />
              <span
                className="relative inline-flex h-3 w-3 rounded-full"
                style={{ backgroundColor: "#2EE59D" }}
              />
            </span>
            <div>
              <div className="text-sm font-semibold hp-healthy">
                {data.status === "ok" ? "All systems operational" : "System degraded"}
              </div>
              <div className="text-xs text-muted-foreground">
                {data.service} · {data.database === "up" ? "database connected" : "database down"}
              </div>
            </div>
          </div>
        </Banner>
      )}

      {/* ── SECONDARY: metric cards ─────────────────────────────────── */}
      {data && (
        <section>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Backend metrics
          </h2>
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
        </section>
      )}

      {/* ── DEBUG: collapsible raw response ─────────────────────────── */}
      <AccordionItem title="View raw response" defaultOpen={false}>
        <pre className="overflow-auto rounded-md p-3 text-xs leading-relaxed hp-live-bg">
          {JSON.stringify(data ?? { loading: true }, null, 2)}
        </pre>
      </AccordionItem>

      {/* ── FOOTER: tertiary reference info ─────────────────────────── */}
      {data && data.status === "ok" && (
        <section className="rounded-md border border-border/60 bg-card/30 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
            <div>
              Next auto-refresh:{" "}
              <span className="font-mono text-foreground/80">
                {formatDateTime(new Date(Date.now() + 15_000).toISOString())}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span>Severity:</span>
              <SeverityBadge value="low" />
              <SeverityBadge value="medium" />
              <SeverityBadge value="high" />
              <SeverityBadge value="critical" />
            </div>
            <div className="flex items-center gap-2">
              <span>Domain:</span>
              <DomainBadge value="IT" />
              <DomainBadge value="OT" />
              <DomainBadge value="IoT" />
            </div>
          </div>
        </section>
      )}
    </div>
  );
}

function Banner({
  tone,
  children,
}: {
  tone: "ok" | "warn" | "bad" | "muted";
  children: React.ReactNode;
}) {
  const cls =
    tone === "ok"
      ? "hp-healthy-bg"
      : tone === "warn"
        ? "hp-warning-bg"
        : tone === "bad"
          ? "hp-critical-bg"
          : "border border-border bg-card";
  return (
    <div className={`relative overflow-hidden rounded-md border p-4 ${cls}`}>
      {/* Signature violet glow — only on the primary banner */}
      {tone === "ok" && <div className="hp-violet-glow absolute inset-0 pointer-events-none" />}
      <div className="relative">{children}</div>
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
  const valueClass =
    tone === "ok"
      ? "hp-healthy-bg hp-healthy"
      : tone === "warn"
        ? "hp-warning-bg hp-warning"
        : tone === "bad"
          ? "hp-critical-bg hp-critical"
          : "hp-live-bg hp-live";
  return (
    <div className="rounded-md border border-border bg-card p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div
        className={`mt-2 inline-flex items-center rounded-md border px-2 py-0.5 text-sm font-medium ${valueClass}`}
      >
        {value}
      </div>
    </div>
  );
}