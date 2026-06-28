import { useLocation } from "react-router-dom";

import HealthPill from "@/components/health/HealthPill";

const TITLES: Record<string, { title: string; subtitle: string }> = {
  "/health": { title: "System Health", subtitle: "Backend, database, and agent pipeline status" },
  "/incidents": { title: "Incidents", subtitle: "Detected events across IT and OT/IoT domains" },
};

export default function Header() {
  const { pathname } = useLocation();
  const meta =
    TITLES[pathname] ??
    (pathname.startsWith("/incidents/")
      ? { title: "Incident Detail", subtitle: "Full agent trace and enrichment" }
      : { title: "HyperPlane", subtitle: "Dual-domain agentic SIEM" });

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-card px-6">
      <div>
        <h1 className="text-base font-semibold leading-tight">{meta.title}</h1>
        <p className="text-xs text-muted-foreground">{meta.subtitle}</p>
      </div>
      <div className="flex items-center gap-3">
        <HealthPill />
      </div>
    </header>
  );
}