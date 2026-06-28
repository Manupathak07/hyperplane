import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Polls /health every 30s and renders a coloured pill in the Header.
 * Green = ok (use --hp-healthy), Red = down (use --hp-critical, only because
 * it IS a real failure state), Amber = loading.
 */
export default function HealthPill() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 30_000,
  });

  if (isLoading) {
    return (
      <Pill className="hp-warning-bg">
        <Loader2 className="h-3.5 w-3.5 animate-spin hp-warning" />
        <span className="hp-warning">checking…</span>
      </Pill>
    );
  }

  if (isError || data?.status !== "ok") {
    return (
      <Pill className="hp-critical-bg">
        <XCircle className="h-3.5 w-3.5 hp-critical" />
        <span className="hp-critical">backend down</span>
      </Pill>
    );
  }

  return (
    <Pill className="hp-healthy-bg">
      <CheckCircle2 className="h-3.5 w-3.5 hp-healthy" />
      <span className="hp-healthy">all systems operational</span>
    </Pill>
  );
}

function Pill({
  tone,
  children,
  className,
}: {
  tone?: never; // tones are picked via hp-* utility classes now
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium",
        className,
      )}
    >
      {children}
    </div>
  );
}