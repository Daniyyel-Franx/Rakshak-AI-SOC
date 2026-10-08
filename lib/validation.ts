import { z } from "zod"

// Zod schemas validate every API response before it reaches the UI.
// A parse failure surfaces a degraded/error state; responses are never
// silently ignored.

export const healthSchema = z.object({
  status: z.string(),
  ollama_available: z.boolean(),
  ollama_model: z.string(),
  database: z.string(),
  ocsf_schema_version: z.string(),
  faiss_available: z.boolean(),
  retrieval_mode: z.string(),
})

export const scenarioSchema = z.object({
  scenario_id: z.string(),
  name: z.string(),
  description: z.string(),
  severity: z.string(),
  ground_truth_nodes: z.number(),
  ground_truth_edges: z.number(),
  benign: z.boolean(),
})
export const scenarioListSchema = z.array(scenarioSchema)

export const ocsfEventSchema = z.object({
  event_id: z.string(),
  event_time: z.string(),
  received_time: z.string(),
  site_id: z.string(),
  event_class: z.string(),
  activity_id: z.number(),
  type_uid: z.number(),
  severity_id: z.number(),
  status_id: z.number(),
  action: z.string(),
  message: z.string(),
  priority: z.number(),
  source: z.record(z.string(), z.unknown()).nullish(),
  destination: z.record(z.string(), z.unknown()).nullish(),
  user: z.record(z.string(), z.unknown()).nullish(),
  device: z.record(z.string(), z.unknown()).nullish(),
  process: z.record(z.string(), z.unknown()).nullish(),
  unmapped: z.record(z.string(), z.unknown()),
  classification: z.string(),
})

export const telemetryPageSchema = z.object({
  items: z.array(ocsfEventSchema),
  next_cursor: z.string().nullable(),
  total: z.number(),
})

const severityLevel = z.enum(["low", "medium", "high", "critical"])

export const graphNodeSchema = z.object({
  id: z.string(),
  type: z.string(),
  position: z.object({ x: z.number(), y: z.number() }),
  data: z.looseObject({
    label: z.string(),
    entity_type: z.string(),
    severity: severityLevel,
    evidence_event_ids: z.array(z.string()),
  }),
})

export const graphEdgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  label: z.string(),
  timestamp: z.string(),
  technique_id: z.string(),
  technique_name: z.string(),
  evidence_event_ids: z.array(z.string()),
  severity: severityLevel,
  animated: z.boolean(),
})

export const graphSchema = z.object({
  nodes: z.array(graphNodeSchema),
  edges: z.array(graphEdgeSchema),
})

export const techniqueSchema = z.object({
  id: z.string(),
  name: z.string(),
  tactic: z.string(),
  confidence: z.number(),
  evidence_refs: z.array(z.string()),
})

export const recommendedStepSchema = z.object({
  action: z.string(),
  risk_class: z.enum(["R0", "R1", "R2", "R3"]),
  requires_approval: z.boolean(),
})

export const incidentSummarySchema = z.object({
  incident_id: z.string(),
  title: z.string(),
  status: z.string(),
  risk_score: z.number(),
  confidence: z.number(),
  mission_impact: z.string(),
  scenario_id: z.string(),
  finding_count: z.number(),
  created_at: z.string(),
  source: z.string().optional().default("demo"),
})
export const incidentListSchema = z.array(incidentSummarySchema)

export const aiAnalysisSchema = z.object({
  incident_id: z.string(),
  assessment: z.string(),
  threat_score: z.number(),
  confidence: z.number(),
  evidence_refs: z.array(z.string()),
  attack_techniques: z.array(techniqueSchema),
  attack_path_summary: z.string(),
  recommended_next_steps: z.array(recommendedStepSchema),
  missing_evidence: z.array(z.string()),
  safety_notice: z.string(),
  analysis_source: z.enum(["ollama", "rule_engine_fallback"]),
})

export const timelineEntrySchema = z.object({
  event_id: z.string(),
  time: z.string(),
  event_class: z.string(),
  message: z.string(),
  severity_id: z.number(),
})

export const incidentDetailSchema = incidentSummarySchema.extend({
  entity_ids: z.array(z.string()),
  finding_ids: z.array(z.string()),
  evidence_refs: z.array(z.string()),
  recommended_actions: z.array(recommendedStepSchema),
  timeline: z.array(timelineEntrySchema),
  graph: graphSchema,
  analysis: z
    .union([aiAnalysisSchema, z.record(z.string(), z.unknown())])
    .nullable()
    .optional()
    .transform((v) => {
      if (v && "assessment" in v && typeof (v as Record<string, unknown>).assessment === "string") {
        const parsed = aiAnalysisSchema.safeParse(v)
        if (parsed.success) return parsed.data
      }
      return null
    }),
})

export const metricsSchema = z.object({
  total_events: z.number(),
  active_incidents: z.number(),
  critical_incidents: z.number(),
  average_risk: z.number(),
  events_per_minute: z.number(),
  queued_offline_events: z.number(),
  severity_counts: z.record(z.string(), z.number()),
  events_by_class: z.record(z.string(), z.number()),
  techniques: z.record(z.string(), z.number()),
  risk_distribution: z.array(z.object({ bucket: z.string(), count: z.number() })),
  event_rate_timeseries: z.array(z.object({ minute: z.string(), count: z.number() })),
  top_entities: z.array(z.object({ entity: z.string(), risk: z.number() })),
  incident_status: z.record(z.string(), z.number()),
  cross_site_campaigns: z.array(
    z.object({
      incident_id: z.string(),
      title: z.string(),
      risk_score: z.number(),
      sites: z.array(z.string()),
    }),
  ),
  provenance_breakdown: z.record(z.string(), z.record(z.string(), z.number())).optional().default({}),
})

export const replaySchema = z.object({
  run_id: z.string(),
  scenario_id: z.string(),
  status: z.string(),
  events_ingested: z.number(),
  duplicates_skipped: z.number(),
  incident_id: z.string().nullable(),
})

export const simulatedActionSchema = z.object({
  action_id: z.string(),
  incident_id: z.string(),
  action_type: z.string(),
  target: z.string(),
  approval_state: z.string(),
  approved_by: z.string().nullable().optional(),
  policy_risk_class: z.string(),
  result: z.string(),
  rollback_data: z.record(z.string(), z.unknown()).optional().default({}),
  rollback: z.record(z.string(), z.unknown()).optional(),
  simulation_only: z.boolean(),
})

// ── Blast Radius ──────────────────────────────────────────────────────────────

export const blastRadiusContributingNodeSchema = z.object({
  node: z.string(),
  weight: z.number(),
  distance: z.number(),
  contribution: z.number(),
})

export const blastRadiusHostSchema = z.object({
  host: z.string(),
  score: z.number(),
  contributing_nodes: z.array(blastRadiusContributingNodeSchema),
})

export const blastRadiusSchema = z.object({
  incident_id: z.string(),
  hosts: z.array(blastRadiusHostSchema),
})
