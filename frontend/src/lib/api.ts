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

import { useEffect } from "react";

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
  raw_event: Record<string, any>;
  threat_intel: Record<string, any>;
  detection_score: number;
  attack_stage: string | null;
  related_incident_ids: string[];
  detection_details: Record<string, any> | null;
  response: Record<string, any> | null;
  created_at: string;
  updated_at: string;
}

/**
 * Hook to subscribe to real-time event updates via WebSocket.
 * Returns the latest event and a function to disconnect.
 */
export function useEventStream(onEvent: (event: Incident) => void) {
  useEffect(() => {
    const ws = new WebSocket(`${import.meta.env.VITE_WS_URL || ""
      .replace(/^http/, "ws")
      .replace(/\/api$/, "")}/ws/events/`);

    const handleMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "event" && data.data) {
          // Convert WebSocket event format to Incident format
          const incident: Incident = {
            id: data.data.id,
            event_id: data.data.event_id,
            event_type: data.data.event_type,
            correlation_id: data.data.correlation_id,
            title: data.data.title,
            description: data.data.description,
            source: data.data.source,
            domain: data.data.domain as Domain,
            severity: data.data.severity as Severity,
            status: data.data.status as IncidentStatus,
            raw_event: data.data.raw_event,
            threat_intel: data.data.threat_intel || {},
            detection_score: data.data.detection_score || 0,
            attack_stage: data.data.attack_stage,
            related_incident_ids: data.data.related_incident_ids || [],
            detection_details: data.data.detection_details,
            response: data.data.response,
            created_at: data.data.created_at,
            updated_at: data.data.updated_at,
          };
          onEvent(incident);
        }
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };

    ws.addEventListener("message", handleMessage);
    ws.addEventListener("open", () => console.log("WebSocket connected"));
    ws.addEventListener("error", (e) => console.error("WebSocket error:", e));
    ws.addEventListener("close", () => console.log("WebSocket disconnected"));

    return () => {
      ws.close();
    };
  }, [onEvent]);
}

/**
 * Hook to subscribe to real-time trace updates for a specific incident.
 * Returns the latest trace and a function to disconnect.
 */
export function useTraceStream(
  incidentId: string | undefined,
  onTrace: (trace: Omit<AgentTrace, "created_at"> & { created_at: string }) => void
) {
  useEffect(() => {
    if (!incidentId) return;

    const ws = new WebSocket(
      `${import.meta.env.VITE_WS_URL || ""
        .replace(/^http/, "ws")
        .replace(/\/api$/, "")}/ws/trace/${incidentId}`
    );

    const handleMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "trace" && data.data && data.data.trace) {
          const trace = data.data.trace;
          // Convert WebSocket trace format to match our AgentTrace type
          const formattedTrace: Omit<AgentTrace, "created_at"> & {
            created_at: string;
          } = {
            id: trace.id,
            incident_id: incidentId,
            agent_name: trace.agent_name as
              | "supervisor"
              | "triage"
              | "threat_intel"
              | "enrichment"
              | "detection"
              | "response",
            step: trace.step,
            input: trace.input,
            output: trace.output,
            reasoning: trace.reasoning,
            duration_ms: trace.duration_ms,
            status: trace.status as "success" | "failed" | "skipped",
            created_at: trace.created_at || new Date().toISOString(),
          };
          onTrace(formattedTrace);
        }
      } catch (e) {
        console.error("Failed to parse WebSocket trace message:", e);
      }
    };

    ws.addEventListener("message", handleMessage);
    ws.addEventListener("open", () =>
      console.log(`WebSocket connected for incident ${incidentId}`)
    );
    ws.addEventListener("error", (e) => console.error("WebSocket error:", e));
    ws.addEventListener("close", () =>
      console.log(`WebSocket disconnected for incident ${incidentId}`)
    );

    return () => {
      ws.close();
    };
  }, [incidentId, onTrace]);
}

// --- API client functions (unchanged) -------------------------------------

async function apiFetch<T>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${typeof input === "string" ? input : ""}`, {
    ...(init ?? {}),
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    credentials: "include",
  });

  if (!res.ok) {
    const err = await getErrorBody(res);
    throw new Error(err.message || `HTTP ${res.status}`);
  }

  return (await res.json()) as T;
}

async function getErrorBody(res: Response): Promise<{ message?: string }> {
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) return await res.json();
  return { message: await res.text() };
}

export const apiGet = <T>(url: string) => apiFetch<T>(url);
export const apiPost = <T, D = unknown>(url: string, data: D) =>
  apiFetch<T>(url, { method: "POST", body: JSON.stringify(data) });
export const apiPut = <T, D = unknown>(url: string, data: D) =>
  apiFetch<T>(url, { method: "PUT", body: JSON.stringify(data) });
export const apiPatch = <T, D = unknown>(url: string, data: D) =>
  apiFetch<T>(url, { method: "PATCH", body: JSON.stringify(data) });
export const apiDelete = <T>(url: string) => apiFetch<T>(url, { method: "DELETE" });

// --- Agent trace type (for WebSocket updates) ---------------------------

export type AgentName =
  | "supervisor"
  | "triage"
  | "threat_intel"
  | "enrichment"
  | "detection"
  | "response";

export interface AgentTrace {
  id: string;
  incident_id: string;
  agent_name: AgentName;
  step: number;
  input: Record<string, any>;
  output: Record<string, any>;
  reasoning: string | null;
  duration_ms: number | null;
  status: "success" | "failed" | "skipped";
  created_at: string;
}
