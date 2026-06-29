import { Link2 } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * Renders a small violet pill indicating that this incident is part of a
 * multi-event correlation (Week 4 scenarios, Week 6 Detection-agent output).
 *
 * Violet is reserved here per the HP palette rules — no other component
 * uses it. Renders nothing when correlation_id is null.
 */
export default function CorrelationBadge({
  correlationId,
}: {
  correlationId: string | null;
}) {
  if (!correlationId) return null;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider",
        "dom-ot", // reuse violet palette token
      )}
      title={`Correlation ID: ${correlationId}`}
    >
      <Link2 className="h-3 w-3" />
      Corr
    </span>
  );
}