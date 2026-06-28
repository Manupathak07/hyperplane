import { NavLink } from "react-router-dom";
import { Activity, AlertTriangle, Gauge, Network, Radar, ScrollText } from "lucide-react";

import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  disabled?: boolean;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV: NavGroup[] = [
  {
    label: "Core",
    items: [
      { to: "/health", label: "Health", icon: Activity },
      { to: "/incidents", label: "Incidents", icon: AlertTriangle },
    ],
  },
  {
    label: "Analysis",
    items: [
      { to: "/correlation", label: "Correlation", icon: Network, disabled: true },
      { to: "/detection", label: "Detection", icon: Radar, disabled: true },
    ],
  },
  {
    label: "Advanced",
    items: [
      { to: "/traces", label: "Agent Traces", icon: ScrollText, disabled: true },
      { to: "/reports", label: "Reports", icon: Gauge, disabled: true },
    ],
  },
];

export default function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 border-r border-border bg-card md:flex md:flex-col">
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/15 text-primary">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="h-4 w-4"
          >
            <path d="M12 2L2 7l10 5 10-5-10-5z" />
            <path d="M2 17l10 5 10-5" />
            <path d="M2 12l10 5 10-5" />
          </svg>
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold leading-tight">HyperPlane</span>
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
            Agentic SIEM
          </span>
        </div>
      </div>

      <nav className="flex-1 space-y-5 p-3">
        {NAV.map((group) => (
          <div key={group.label}>
            <div className="mb-1 px-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
              {group.label}
            </div>
            <div className="space-y-1">
              {group.items.map((item) => {
                const Icon = item.icon;
                const baseClass =
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors";
                if (item.disabled) {
                  return (
                    <div
                      key={item.to}
                      className={cn(
                        baseClass,
                        "cursor-not-allowed text-muted-foreground/60",
                      )}
                      title="Coming soon"
                    >
                      <Icon className="h-4 w-4" />
                      <span className="flex-1">{item.label}</span>
                      <span className="rounded-full bg-muted px-2 py-0.5 text-[9px] font-medium uppercase tracking-wider text-muted-foreground/70">
                        Soon
                      </span>
                    </div>
                  );
                }
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      cn(
                        baseClass,
                        isActive
                          ? "bg-accent text-accent-foreground"
                          : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                      )
                    }
                  >
                    <Icon className="h-4 w-4" />
                    <span className="flex-1">{item.label}</span>
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-border p-3 text-[10px] text-muted-foreground">
        <div>v0.1.0 · Week 3</div>
        <div className="mt-1 text-muted-foreground/60">
          React + Vite + shadcn/ui
        </div>
      </div>
    </aside>
  );
}