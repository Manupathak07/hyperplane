import type { Severity } from "@/lib/api";
import { cn } from "@/lib/utils";

const STYLES: Record<Severity, string> = {
  low: "sev-low",
  medium: "sev-medium",
  high: "sev-high",
  critical: "sev-critical",
};

export default function SeverityBadge({ value }: { value: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        STYLES[value],
      )}
    >
      {value}
    </span>
  );
}