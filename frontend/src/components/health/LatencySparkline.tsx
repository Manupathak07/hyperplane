import { useLatencyTracker } from "@/hooks/useLatencyTracker";

interface Props {
  intervalMs?: number;
  height?: number;
}

/**
 * SVG sparkline of recent /health response latency.
 * Cyan-only gradient — cyan is reserved for live data, never for interactive UI.
 */
export default function LatencySparkline({ intervalMs = 5_000, height = 60 }: Props) {
  const { samples, last } = useLatencyTracker(intervalMs);

  if (samples.length === 0) {
    return (
      <div
        className="flex items-center justify-center text-xs text-muted-foreground"
        style={{ height }}
      >
        collecting samples…
      </div>
    );
  }

  const W = 240;
  const H = height;
  const P = 6;
  const max = Math.max(...samples.map((s) => s.ms), 50);
  const min = Math.min(...samples.map((s) => s.ms), 0);
  const range = Math.max(max - min, 1);

  const xStep = (W - P * 2) / Math.max(samples.length - 1, 1);
  const pts = samples.map((s, i) => {
    const x = P + i * xStep;
    const y = H - P - ((s.ms - min) / range) * (H - P * 2);
    return [x, y] as const;
  });
  const path = pts
    .map(([x, y], i) => (i === 0 ? `M${x},${y}` : `L${x},${y}`))
    .join(" ");
  const areaPath = `${path} L${pts[pts.length - 1][0]},${H - P} L${pts[0][0]},${H - P} Z`;

  const avg = samples.reduce((acc, s) => acc + s.ms, 0) / samples.length;

  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between">
        <div className="text-lg tabular-nums" style={{ color: "#3BC7FF" }}>
          {last ? `${last.ms}` : "—"}
          <span className="ml-1 text-xs text-muted-foreground">ms</span>
        </div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
          avg {Math.round(avg)}ms · {samples.length}/60
        </div>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height={H}
        preserveAspectRatio="none"
        className="block"
      >
        <defs>
          <linearGradient id="spark-grad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#3BC7FF" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#3BC7FF" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={areaPath} fill="url(#spark-grad)" />
        <path
          d={path}
          fill="none"
          stroke="#3BC7FF"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        {pts.length > 0 && (
          <circle
            cx={pts[pts.length - 1][0]}
            cy={pts[pts.length - 1][1]}
            r="2.5"
            fill="#3BC7FF"
            className="animate-pulse"
          />
        )}
      </svg>
    </div>
  );
}