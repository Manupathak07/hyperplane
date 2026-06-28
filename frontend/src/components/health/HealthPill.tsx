import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Polls /health every 30s and renders a coloured pill in the Header.
 * Green = ok, Red = down/errored, Amber = loading.
 */
export default function HealthPill() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 30_000,
  });

  if (isLoading) {
    return (
      <Pill tone="muted">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        <span>checking…</span>
      </Pill>
    );
  }

  if (isError || data?.status !== "ok") {
    return (
      <Pill tone="destructive">
        <XCircle className="h-3.5 w-3.5" />
        <span>backend down</span>
      </Pill>
    );
  }

  return (
    <Pill tone="ok">
      <CheckCircle2 className="h-3.5 w-3.5" />
      <span>all systems operational</span>
    </Pill>
  );
}

function Pill({
  tone,
  children,
}: {
  tone: "ok" | "muted" | "destructive";
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium",
        tone === "ok" &&
          "border-emerald-500/30 bg-emerald-500/15 text-emerald-300",
        tone === "muted" &&
          "border-border bg-muted text-muted-foreground",
        tone === "destructive" &&
          "border-red-500/30 bg-red-500/15 text-red-300",
      )}
    >
      {children}
    </div>
  );
}