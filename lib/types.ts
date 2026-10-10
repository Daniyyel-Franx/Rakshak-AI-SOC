// Rakshak-AI frontend types. Mirror of backend Pydantic response models.
// No `any` is used for API data anywhere in the app.

export type ConnectionMode = "live" | "seeded"

export interface HealthResponse {
  status: string
  ollama_available: boolean
  ollama_model: string
  database: string
  ocsf_schema_version: string
  faiss_available: boolean
  retrieval_mode: string
}

export interface ScenarioSummary {
  scenario_id: string
  name: string
  description: string
  severity: string
  ground_truth_nodes: number
  ground_truth_edges: number
  benign: boolean
}

export interface OcsfEvent {
  event_id: string
  event_time: string
  received_time: string
  site_id: string
  event_class: string
  activity_id: number
  type_uid: number
  severity_id: number
  status_id: number
  action: string
  message: string
  priority: number
  source?: Record<string, unknown> | null
  destination?: Record<string, unknown> | null
  user?: Record<string, unknown> | null
  device?: Record<string, unknown> | null
  process?: Record<string, unknown> | null
  unmapped: Record<string, unknown>
  classification: string
}

export interface TelemetryPage {
  items: OcsfEvent[]
  next_cursor: string | null
  total: number
}

export type SeverityLevel = "low" | "medium" | "high" | "critical"

export interface GraphNodeData {
  label: string
  entity_type: string
  severity: SeverityLevel
  evidence_event_ids: string[]
  [key: string]: unknown
}

export interface GraphNode {
  id: string
  type: string
  position: { x: number; y: number }
  data: GraphNodeData
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  label: string
  timestamp: string
  technique_id: string
  technique_name: string
  evidence_event_ids: string[]
  severity: SeverityLevel
  animated: boolean
}

export interface IncidentGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface AttackTechnique {
  id: string
  name: string
  tactic: string
  confidence: number
  evidence_refs: string[]
}

export interface RecommendedStep {
  action: string
  risk_class: "R0" | "R1" | "R2" | "R3"
  requires_approval: boolean
}

export interface IncidentSummary {
  incident_id: string
  title: string
  status: string
  risk_score: number
  confidence: number
  mission_impact: string
  scenario_id: string
  finding_count: number
  created_at: string
  source?: string
}

export interface TimelineEntry {
  event_id: string
  time: string
  event_class: string
  message: string
  severity_id: number
}

export interface IncidentDetail extends IncidentSummary {
  entity_ids: string[]
  finding_ids: string[]
  evidence_refs: string[]
  recommended_actions: RecommendedStep[]
  timeline: TimelineEntry[]
  graph: IncidentGraph
  analysis?: AiAnalysis | null
}

export interface AiAnalysis {
  incident_id: string
  assessment: string
  threat_score: number
  confidence: number
  evidence_refs: string[]
  attack_techniques: AttackTechnique[]
  attack_path_summary: string
  recommended_next_steps: RecommendedStep[]
  missing_evidence: string[]
  safety_notice: string
  analysis_source: "ollama" | "rule_engine_fallback"
}

export interface MetricsSummary {
  total_events: number
  active_incidents: number
  critical_incidents: number
  average_risk: number
  events_per_minute: number
  queued_offline_events: number
  severity_counts: Record<string, number>
  events_by_class: Record<string, number>
  techniques: Record<string, number>
  risk_distribution: { bucket: string; count: number }[]
  event_rate_timeseries: { minute: string; count: number }[]
  top_entities: { entity: string; risk: number }[]
  incident_status: Record<string, number>
  cross_site_campaigns: { incident_id: string; title: string; risk_score: number; sites: string[] }[]
  provenance_breakdown: Record<string, Record<string, number>>
}

export interface ReplayResponse {
  run_id: string
  scenario_id: string
  status: string
  events_ingested: number
  duplicates_skipped: number
  incident_id: string | null
  queued?: boolean
}

export interface SimulatedActionResponse {
  action_id: string
  incident_id: string
  action_type: string
  target: string
  approval_state: string
  approved_by?: string | null
  policy_risk_class: string
  result: string
  rollback_data: Record<string, unknown>
  rollback?: Record<string, unknown>
  simulation_only: boolean
}

export interface ConnectionState {
  mode: ConnectionMode
  online: boolean
  queued: number
}

// ── Blast Radius ──────────────────────────────────────────────────────────────

export interface BlastRadiusContributingNode {
  node: string
  weight: number
  distance: number
  contribution: number
}

export interface BlastRadiusTopologyEdge {
  source: string
  target: string
  trust_type?: string
}

export interface BlastRadiusHostResult {
  host: string
  canonical_host?: string
  score: number
  contributing_nodes: BlastRadiusContributingNode[]
  topology_edges?: BlastRadiusTopologyEdge[]
  error?: string
}

export interface BlastRadiusResponse {
  incident_id: string
  hosts: BlastRadiusHostResult[]
}
