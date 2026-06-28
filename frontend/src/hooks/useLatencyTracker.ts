import { useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";

const MAX_SAMPLES = 60;

/**
 * Measures /health response latency on a fixed interval and keeps a rolling
 * window of the last MAX_SAMPLES readings. Used by LatencySparkline and
 * LiveIndicator.
 *
 * Returns:
 *  - samples: array of { t: epoch ms, ms: latency in ms }
 *  - last: most recent sample (or null until first measurement)
 *  - isStale: true if no sample in the last 2 intervals (probably offline)
 */
export function useLatencyTracker(intervalMs = 5_000) {
  const [samples, setSamples] = useState<{ t: number; ms: number }[]>([]);
  const tickRef = useRef<number | null>(null);

  useEffect(() => {
    const tick = async () => {
      const t0 = performance.now();
      try {
        await api.health();
        const ms = Math.round(performance.now() - t0);
        setSamples((prev) => {
          const next = [...prev, { t: Date.now(), ms }];
          return next.slice(-MAX_SAMPLES);
        });
      } catch {
        // record an error as a "high latency" sample so the sparkline shows it
        setSamples((prev) => {
          const next = [
            ...prev,
            { t: Date.now(), ms: intervalMs * 2 },
          ];
          return next.slice(-MAX_SAMPLES);
        });
      }
    };

    // First sample immediately, then on interval
    tick();
    tickRef.current = window.setInterval(tick, intervalMs);
    return () => {
      if (tickRef.current) window.clearInterval(tickRef.current);
    };
  }, [intervalMs]);

  const last = samples.length > 0 ? samples[samples.length - 1] : null;
  const isStale =
    last !== null && Date.now() - last.t > intervalMs * 2 + 1_000;

  return { samples, last, isStale };
}