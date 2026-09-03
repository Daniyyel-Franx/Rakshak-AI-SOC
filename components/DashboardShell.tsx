"use client"

import { useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { Shield, ExternalLink, ChevronRight } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ConnectionStatus } from "@/components/ConnectionStatus"
import { RiskSummary } from "@/components/RiskSummary"
import { ScenarioControls } from "@/components/ScenarioControls"
import { AttackPathGraph } from "@/components/AttackPathGraph"
import { TelemetryFeed } from "@/components/TelemetryFeed"
import { SeverityChart, RiskHistogram } from "@/components/SeverityChart"
import { TechniqueChart } from "@/components/TechniqueChart"
import { EntityRiskTable } from "@/components/EntityRiskTable"
import { IncidentTimeline } from "@/components/IncidentTimeline"
import { AIInsightPanel } from "@/components/AIInsightPanel"
import { ResponseActions } from "@/components/ResponseActions"
import { useIncidents, useIncident, useMetrics } from "@/lib/hooks"
import { riskTone, SEVERITY_COLOR, fmtDateTime } from "@/lib/ui"
import type { GraphNode } from "@/lib/types"

const ALL_SITES = "__all__"

export function DashboardShell() {
  const { data: incidents } = useIncidents()
  const { data: metrics } = useMetrics()
  const [selectedIncident, setSelectedIncident] = useState<string | null>(null)
  const [site, setSite] = useState<string>(ALL_SITES)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  // Auto-select the highest-risk incident once loaded.
  useEffect(() => {
    if (!selectedIncident && incidents && incidents.length > 0) {
      const top = [...incidents].sort((a, b) => b.risk_score - a.risk_score)[0]
      setSelectedIncident(top.incident_id)
    }
  }, [incidents, selectedIncident])

  const { data: incident } = useIncident(selectedIncident)

  const sites = useMemo(() => {
    const set = new Set<string>()
    ;(metrics?.top_entities ?? []).forEach(() => {})
    ;(incidents ?? []).forEach((i) => i.scenario_id && set.add(i.scenario_id))
    return ["site-01", "site-02", "site-03"]
  }, [metrics, incidents])

  const activeTarget =
    (incident?.entity_ids ?? []).find((e) => e.startsWith("target_host:"))?.split(":")[1] ??
    (incident?.entity_ids ?? [])[0]?.split(":")[1] ??
    "synthetic-target"

  return (
    <div className="min-h-screen bg-background">
      {/* Top bar */}
      <header className="sticky top-0 z-30 border-b border-border bg-sidebar/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-[var(--chart-1)]/15">
              <Shield className="h-4.5 w-4.5 text-[var(--chart-1)]" />
            </div>
            <div className="leading-tight">
              <h1 className="text-sm font-semibold tracking-tight">Rakshak-AI</h1>
              <p className="text-[10px] text-muted-foreground">Mission-Aware Cyber Defence SOC</p>
            </div>
            <Badge
              variant="outline"
              className="ml-1 border-[var(--chart-2)] text-[9px] text-[var(--chart-2)]"
            >
              SYNTHETIC CYBER-RANGE
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Site</span>
            <Select value={site} onValueChange={(v) => setSite(v ?? ALL_SITES)}>
              <SelectTrigger className="h-7 w-[120px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL_SITES}>All sites</SelectItem>
                {sites.map((s) => (
                  <SelectItem key={s} value={s} className="text-xs">
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="ml-auto flex items-center gap-4">
            <ConnectionStatus />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] space-y-4 px-4 py-4">
        <RiskSummary />

        {/* Row: controls + graph */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[300px_1fr]">
          <div className="space-y-4">
            <ScenarioControls onReplay={setSelectedIncident} />
            <IncidentList
              incidents={incidents ?? []}
              selectedId={selectedIncident}
              onSelect={setSelectedIncident}
            />
          </div>

          <Card className="flex flex-col gap-2 overflow-hidden p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold">Attack pathway</h2>
                <p className="text-xs text-muted-foreground">
                  {incident
                    ? incident.title
                    : "Deterministic graph — backend constructs nodes & edges from telemetry."}
                </p>
              </div>
              {incident ? (
                <Link
                  href={`/incidents/${incident.incident_id}`}
                  className="flex items-center gap-1 text-xs text-[var(--chart-1)] hover:underline"
                >
                  Open full incident <ExternalLink className="h-3 w-3" />
                </Link>
              ) : null}
            </div>
            <div className="h-[440px]">
              <AttackPathGraph graph={incident?.graph} onSelectNode={setSelectedNode} />
            </div>
            {selectedNode ? (
              <NodeEvidence node={selectedNode} />
            ) : (
              <p className="text-[11px] text-muted-foreground">
                Click a node to inspect its evidence event IDs.
              </p>
            )}
          </Card>
        </div>

        {/* Row: telemetry + AI + response */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <TelemetryFeed />
          <AIInsightPanel incidentId={selectedIncident} initial={incident?.analysis} key={selectedIncident} />
          <div className="space-y-4">
            <ResponseActions incidentId={selectedIncident} target={activeTarget} />
            {incident ? <IncidentTimeline timeline={incident.timeline} /> : null}
          </div>
        </div>

        {/* Row: charts */}
        <SeverityChart metrics={metrics} />
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <TechniqueChart metrics={metrics} />
          <RiskHistogram metrics={metrics} />
          <EntityRiskTable metrics={metrics} />
        </div>

        {/* Cross-site campaign view */}
        <CampaignView />

        <footer className="pb-6 pt-2 text-center text-[11px] text-muted-foreground">
          Rakshak-AI is a synthetic cyber-range demonstrator. All attacks, telemetry, deception and
          response actions are simulated. Not production-certified or military-grade.
        </footer>
      </main>
    </div>
  )
}

function IncidentList({
  incidents,
  selectedId,
  onSelect,
}: {
  incidents: { incident_id: string; title: string; risk_score: number; status: string; scenario_id: string; created_at: string }[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <Card className="flex flex-col gap-2 p-4">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Incidents ({incidents.length})
      </h3>
      {incidents.length === 0 ? (
        <p className="py-4 text-center text-xs text-muted-foreground">
          No incidents. Replay a scenario.
        </p>
      ) : (
        <div className="space-y-1.5">
          {[...incidents]
            .sort((a, b) => b.risk_score - a.risk_score)
            .map((i) => {
              const tone = riskTone(i.risk_score)
              const active = i.incident_id === selectedId
              return (
                <button
                  key={i.incident_id}
                  onClick={() => onSelect(i.incident_id)}
                  className={`flex w-full items-center gap-2 rounded-md border px-2.5 py-2 text-left transition-colors ${
                    active ? "border-[var(--chart-1)] bg-[var(--chart-1)]/10" : "border-border bg-secondary/40 hover:bg-secondary"
                  }`}
                >
                  <span
                    className="h-8 w-1 rounded-full"
                    style={{ backgroundColor: SEVERITY_COLOR[tone] }}
                    aria-hidden
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs text-foreground">{i.title}</p>
                    <p className="font-mono text-[9px] text-muted-foreground">
                      {i.scenario_id.replace("SCENARIO_", "S")} · {i.status}
                    </p>
                  </div>
                  <span className="font-mono text-xs font-semibold" style={{ color: SEVERITY_COLOR[tone] }}>
                    {i.risk_score.toFixed(0)}
                  </span>
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                </button>
              )
            })}
        </div>
      )}
    </Card>
  )
}

function NodeEvidence({ node }: { node: GraphNode }) {
  return (
    <div className="rounded-md border bg-background px-3 py-2">
      <div className="flex items-center gap-2">
        <Badge variant="outline" className="text-[9px]">
          {node.data.entity_type}
        </Badge>
        <span className="font-mono text-xs text-foreground">{node.data.label}</span>
        <Badge
          className="ml-auto text-[9px]"
          style={{
            backgroundColor: `color-mix(in oklch, ${SEVERITY_COLOR[node.data.severity]} 18%, transparent)`,
            color: SEVERITY_COLOR[node.data.severity],
          }}
        >
          {node.data.severity}
        </Badge>
      </div>
      <p className="mt-1 font-mono text-[10px] text-muted-foreground">
        evidence: {node.data.evidence_event_ids.join(", ") || "none"}
      </p>
    </div>
  )
}

function CampaignView() {
  const { data: metrics } = useMetrics()
  const campaigns = metrics?.cross_site_campaigns ?? []
  if (campaigns.length === 0) return null
  return (
    <Card className="flex flex-col gap-2 p-4">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Cross-site campaign view
      </h3>
      <div className="space-y-1.5">
        {campaigns.map((c) => (
          <Link
            key={c.incident_id}
            href={`/incidents/${c.incident_id}`}
            className="flex items-center gap-2 rounded-md border border-[var(--chart-3)]/40 bg-[var(--chart-3)]/5 px-3 py-2 transition-colors hover:bg-[var(--chart-3)]/10"
          >
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs text-foreground">{c.title}</p>
              <p className="font-mono text-[10px] text-muted-foreground">
                sites: {c.sites.join(", ")}
              </p>
            </div>
            <span className="font-mono text-xs font-semibold text-[var(--chart-3)]">
              {c.risk_score.toFixed(0)}
            </span>
          </Link>
        ))}
      </div>
    </Card>
  )
}
