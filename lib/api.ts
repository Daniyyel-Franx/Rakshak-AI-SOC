import { z } from "zod"
import seed from "./seed-data.json"
import {
  healthSchema,
  scenarioListSchema,
  telemetryPageSchema,
  incidentListSchema,
  incidentDetailSchema,
  graphSchema,
  metricsSchema,
  aiAnalysisSchema,
  replaySchema,
  simulatedActionSchema,
  blastRadiusSchema,
} from "./validation"
import type {
  HealthResponse,
  ScenarioSummary,
  TelemetryPage,
  IncidentSummary,
  IncidentDetail,
  IncidentGraph,
  MetricsSummary,
  AiAnalysis,
  ReplayResponse,
  SimulatedActionResponse,
  BlastRadiusResponse,
  ConnectionMode,
} from "./types"

// Base URL of the local FastAPI backend. When unreachable (e.g. inside the
// v0 preview or fully offline), the client transparently serves bundled
// seeded data and reports mode="seeded" so the UI shows a degraded banner.
const configuredApiBase = process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "")
// `/api` is a common project default, but this app's same-origin bridge lives
// at `/api/backend` to avoid colliding with Next route handlers.
export const API_BASE = configuredApiBase === "/api" ? "/api/backend" : configuredApiBase || "/api/backend"

let liveMode: ConnectionMode = "seeded"
export function getMode(): ConnectionMode {
  return liveMode
}

type Listener = (mode: ConnectionMode) => void
const listeners = new Set<Listener>()
export function onModeChange(fn: Listener) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}
function setMode(mode: ConnectionMode) {
  if (mode !== liveMode) {
    liveMode = mode
    listeners.forEach((l) => l(mode))
  }
}

async function req<T>(
  path: string,
  schema: z.ZodType<T>,
  fallback: () => T,
  init?: RequestInit,
): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
      signal: AbortSignal.timeout(6000),
    })
  } catch (netErr) {
    if (init?.method && init.method.toUpperCase() !== "GET") {
      throw new Error(`Network error on mutation for ${path}: ${String(netErr)}`)
    }
    // Backend offline / connection refused / timeout -> serve seeded fallback
    setMode("seeded")
    return fallback()
  }

  // Server responded:
  if (!res.ok) {
    // HTTP error from reachable server: surface error instead of masking
    throw new Error(`HTTP ${res.status}: API request failed for ${path}`)
  }

  const json = (await res.json()) as unknown
  try {
    const parsed = schema.parse(json)
    setMode("live")
    return parsed
  } catch (schemaErr) {
    // Live backend returned data, but schema validation failed:
    // Report as error so it is visible to UI instead of silently appearing valid.
    console.error(`[API Schema Mismatch] ${path}:`, schemaErr)
    throw new Error(
      `Schema validation error for ${path}: ${schemaErr instanceof Error ? schemaErr.message : String(schemaErr)}`,
    )
  }
}

// ---- seeded fallbacks (validated the same way as live data) ----
const S = seed as unknown as {
  health: unknown
  scenarios: unknown
  telemetry: unknown
  incidents: unknown
  metrics: unknown
  details: Record<string, unknown>
}

export async function getHealth(): Promise<HealthResponse> {
  return req("/api/health", healthSchema, () => {
    const h = healthSchema.parse(S.health)
    return { ...h, status: "seeded", database: "seeded" }
  })
}

export async function getScenarios(): Promise<ScenarioSummary[]> {
  return req("/api/scenarios", scenarioListSchema, () => scenarioListSchema.parse(S.scenarios))
}

export async function getTelemetry(limit = 60): Promise<TelemetryPage> {
  return req(`/api/telemetry?limit=${limit}`, telemetryPageSchema, () =>
    telemetryPageSchema.parse(S.telemetry),
  )
}

export async function getIncidents(): Promise<IncidentSummary[]> {
  return req("/api/incidents", incidentListSchema, () => incidentListSchema.parse(S.incidents))
}

export async function getIncident(id: string): Promise<IncidentDetail> {
  return req(`/api/incidents/${id}`, incidentDetailSchema, () => {
    const raw = S.details[id]
    if (!raw) throw new Error("not found in seed")
    return incidentDetailSchema.parse(raw)
  })
}

export async function getIncidentGraph(id: string): Promise<IncidentGraph> {
  return req(`/api/incidents/${id}/graph`, graphSchema, () => {
    const raw = S.details[id] as { graph?: unknown } | undefined
    return graphSchema.parse(raw?.graph ?? { nodes: [], edges: [] })
  })
}

export async function getMetrics(): Promise<MetricsSummary> {
  return req("/api/metrics/summary", metricsSchema, () => metricsSchema.parse(S.metrics))
}

export async function analyzeIncident(id: string): Promise<AiAnalysis> {
  return req(
    `/api/analyze/${id}`,
    aiAnalysisSchema,
    () => {
      const raw = S.details[id] as { analysis?: unknown } | undefined
      return aiAnalysisSchema.parse(raw?.analysis)
    },
    { method: "POST" },
  )
}

export async function replayScenario(scenarioId: string): Promise<ReplayResponse> {
  return req(
    `/api/scenarios/${scenarioId}/replay`,
    replaySchema,
    () => ({
      run_id: `seed-${scenarioId}`,
      scenario_id: scenarioId,
      status: "seeded",
      events_ingested: 0,
      duplicates_skipped: 0,
      incident_id:
        (S.incidents as IncidentSummary[]).find((i) => i.scenario_id === scenarioId)
          ?.incident_id ?? null,
    }),
    { method: "POST" },
  )
}

export async function simulateAction(body: {
  incident_id: string
  action_type: string
  target: string
  approved_by?: string
}): Promise<SimulatedActionResponse> {
  return req(
    `/api/actions/simulate`,
    simulatedActionSchema,
    () => ({
      action_id: `seed-act-${Date.now()}`,
      incident_id: body.incident_id,
      action_type: body.action_type,
      target: body.target,
      approval_state: body.approved_by ? "approved" : "pending_approval",
      approved_by: body.approved_by ?? null,
      policy_risk_class: "R2",
      result: body.approved_by
        ? "SIMULATED: action executed against synthetic range only. No real change."
        : "SIMULATED: awaiting approval.",
      rollback_data: { restore: "synthetic snapshot", simulated: true },
      rollback: { restore: "synthetic snapshot", simulated: true },
      simulation_only: true,
    }),
    { method: "POST", body: JSON.stringify(body) },
  )
}

// Link-loss / restore controls (best-effort; seeded no-ops offline).
export async function setLink(online: boolean): Promise<{ online: boolean; queued: number }> {
  const path = online ? "/api/scenarios/link/restore" : "/api/scenarios/link/down"
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    signal: AbortSignal.timeout(6000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const j = (await res.json()) as {
    online?: boolean
    link_down?: boolean
    queued?: number
    queued_offline_events?: number
  }
  const isOnline = j.online !== undefined ? j.online : (j.link_down !== undefined ? !j.link_down : online)
  const queueCount = j.queued ?? j.queued_offline_events ?? 0
  return { online: isOnline, queued: queueCount }
}

export async function getLinkStatus(): Promise<{ online: boolean; queued: number }> {
  const res = await fetch(`${API_BASE}/api/scenarios/link/status`, {
    signal: AbortSignal.timeout(6000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const j = (await res.json()) as {
    online?: boolean
    link_down?: boolean
    queued?: number
    queued_offline_events?: number
  }
  const isOnline = j.online !== undefined ? j.online : (j.link_down !== undefined ? !j.link_down : true)
  const queueCount = j.queued ?? j.queued_offline_events ?? 0
  return { online: isOnline, queued: queueCount }
}

export interface IngestResponse {
  source_type: string
  ingested: number
  duplicates: number
  errors: string[]
  incident_id: string | null
  status: string
}

export async function ingestRawLogs(body: {
  source_type: string
  records: unknown[]
  site_id?: string
}): Promise<IngestResponse> {
  const res = await fetch(`${API_BASE}/api/ingest/raw`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`Ingest failed (${res.status}): ${text || res.statusText}`)
  }
  return res.json()
}

export async function ingestLogFile(
  file: File,
  sourceType: string,
  siteId: string = "site-01",
): Promise<IngestResponse> {
  const formData = new FormData()
  formData.append("file", file)
  formData.append("source_type", sourceType)
  formData.append("site_id", siteId)

  const res = await fetch(`${API_BASE}/api/ingest/file`, {
    method: "POST",
    body: formData,
    signal: AbortSignal.timeout(30000),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`File ingest failed (${res.status}): ${text || res.statusText}`)
  }
  return res.json()
}

export async function getBlastRadius(incidentId: string): Promise<BlastRadiusResponse> {
  return req(
    `/api/incidents/${incidentId}/blast-radius`,
    blastRadiusSchema,
    () => ({ incident_id: incidentId, hosts: [] }),
  )
}

export async function clearDemo(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/api/scenarios/clear`, {
    method: "POST",
    signal: AbortSignal.timeout(6000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return (await res.json()) as { status: string }
}
