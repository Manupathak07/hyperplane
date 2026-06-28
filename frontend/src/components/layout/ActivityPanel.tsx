import LatencySparkline from "@/components/health/LatencySparkline";
import RecentEventsTimeline from "@/components/health/RecentEventsTimeline";

/**
 * Right-side rail shown on every page inside <AppLayout />.
 * Provides persistent "live system" widgets:
 *   - Latency sparkline (real /health response times)
 *   - Recent events timeline (last incidents, polled every 15s)
 *
 * Hidden on viewports < lg to keep mobile usable.
 */
export default function ActivityPanel() {
  return (
    <aside className="hidden w-72 shrink-0 border-l border-border bg-card/40 p-4 lg:block">
      <div className="space-y-5">
        <section>
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              API latency
            </h3>
            <span className="text-[10px] text-muted-foreground/70">
              last 60 samples
            </span>
          </div>
          <LatencySparkline />
        </section>
        <section className="border-t border-border/60 pt-5">
          <RecentEventsTimeline limit={6} />
        </section>
      </div>
    </aside>
  );
}