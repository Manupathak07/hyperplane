import type { Severity } from "@/lib/api";
import { cn } from "@/lib/utils";

const STYLES: Record<Severity, string> = {
  low: "sev-low",
  medium: "sev-medium",
  high: "sev-high",
  critical: "sev-critical",
};

/**
 * Renders a severity pill. When `numeric` is provided (0-10) we show the
 * number — useful for the dashboard where the precise level matters more
 * than the bucketed label. Falls back to the categorical label otherwise.
 */
export default function SeverityBadge({
  value,
  numeric,
}: {
  value: Severity;
  numeric?: number | null;
}) {
  const display =
    typeof numeric === "number" ? numeric.toString() : value.toUpperCase();
  return (
    <span
      className={cn(
        "inline-flex h-6 min-w-[2rem] items-center justify-center rounded-md border px-2 text-xs font-semibold tabular-nums",
        STYLES[value],
      )}
      title={typeof numeric === "number" ? `Severity ${numeric}/10` : value}
    >
      {display}
    </span>
  );
}