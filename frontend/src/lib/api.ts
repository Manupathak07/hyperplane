/**
 * Typed API client for the HyperPlane backend.
 *
 * - All requests go through `/api/*` (proxied to http://localhost:8000 in dev,
 *   and served by nginx in production).
 * - Errors are normalised into a single `ApiError` shape so React Query can
 *   display consistent messages across pages.
 * - Every page should call `apiGet<T>()` inside a `useQuery()` — never
 *   `fetch()` directly.
 */

const API_BASE = "/api";

// --- Shared types (mirror backend Pydantic schemas) -----------------------

export type Severity = "low" | "medium" | "high" | "critical";
export type Domain = "IT" | "OT" | "IoT";
export type IncidentStatus =
  | "new"
  | "triaging"
  | "investigating"
  | "contained"
  | "closed";

export interface HealthResponse {
  status: "ok" | "degraded";
  service: string;
  database: "up" | "down";
}

export interface Incident {
  id: string;
  event_id: string;
  event_type: string | null;
  correlation_id: string | null;
  title: string;
  description: string | null;
  source: string;
  domain: Domain;
  severity: Severity;
  status: IncidentStatus;
  raw_event: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface AgentTrace {
  id: string;
  incident_id: string;
  agent_name:
    | "supervisor"
    | "triage"
    | "threat_intel"
    | "enrichment"
    | "detection"
    | "response";
  step: number;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  reasoning: string | null;
  duration_ms: number | null;
  status: "success" | "failed" | "skipped";
  created_at: string;
}

// --- Error class ---------------------------------------------------------

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public url: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// --- Core fetch wrapper --------------------------------------------------

async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? JSON.stringify(body);
    } catch {
      /* not JSON, keep statusText */
    }
    throw new ApiError(detail, res.status, url);
  }

  // 204 No Content
  if (res.status === 204) return undefined as T;

  return (await res.json()) as T;
}

export const apiGet = <T>(path: string) => apiFetch<T>(path, { method: "GET" });
export const apiPost = <T>(path: string, body: unknown) =>
  apiFetch<T>(path, { method: "POST", body: JSON.stringify(body) });

// --- Endpoint helpers (preferred over raw apiGet) ------------------------

export const api = {
  health: () => apiGet<HealthResponse>("/health"),
  listIncidents: (limit = 200) =>
    apiGet<Incident[]>(`/incidents/?limit=${limit}`),
  getIncident: (id: string) => apiGet<Incident>(`/incidents/${id}`),
} as const;