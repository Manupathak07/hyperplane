import type { Domain } from "@/lib/api";
import { cn } from "@/lib/utils";

const STYLES: Record<Domain, string> = {
  IT: "dom-it",
  OT: "dom-ot",
  IoT: "dom-iot",
};

export default function DomainBadge({ value }: { value: Domain }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        STYLES[value],
      )}
    >
      {value}
    </span>
  );
}