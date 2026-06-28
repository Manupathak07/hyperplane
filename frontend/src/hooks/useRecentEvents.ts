import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";

/**
 * Returns the most recent N incidents for the activity rail timeline.
 * Refetches on a slow interval so the dashboard feels live without hammering
 * the backend.
 */
export function useRecentEvents(limit = 8) {
  return useQuery({
    queryKey: ["incidents", "recent", limit],
    queryFn: () => api.listIncidents(limit),
    refetchInterval: 15_000,
    staleTime: 5_000,
  });
}