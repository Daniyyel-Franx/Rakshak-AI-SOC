"use client"

import { useEffect, useMemo, useState, useRef } from "react"
import Link from "next/link"
import {
  Shield,
  ExternalLink,
  ChevronRight,
  Search,
  Activity,
  Crosshair,
  Radio,
  SlidersHorizontal,
  Layers,
  Cpu,
  Lock,
  Flame,
  Clock,
  Sparkles,
  Upload,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
import { LogIngestionModal } from "@/components/LogIngestionModal"
import { AttackPathGraph } from "@/components/AttackPathGraph"
import { BlastRadiusNetworkView } from "@/components/BlastRadiusNetworkView"
import { BlastRadiusReadout } from "@/components/BlastRadiusReadout"
import { TelemetryFeed } from "@/components/TelemetryFeed"
import { SeverityChart, RiskHistogram } from "@/components/SeverityChart"
import { TechniqueChart } from "@/components/TechniqueChart"
import { EntityRiskTable } from "@/components/EntityRiskTable"
import { IncidentTimeline } from "@/components/IncidentTimeline"
import { AIInsightPanel } from "@/components/AIInsightPanel"
import { ResponseActions } from "@/components/ResponseActions"
import { useIncidents, useIncident, useMetrics } from "@/lib/hooks"
import { getBlastRadius } from "@/lib/api"
import { riskTone, SEVERITY_COLOR, fmtDateTime } from "@/lib/ui"
import type { GraphNode, BlastRadiusResponse, BlastRadiusHostResult } from "@/lib/types"

const ALL_SITES = "__all__"

const SCENARIO_SITE_MAP: Record<string, string[]> = {
  SCENARIO_1_SSH_COMPROMISE: ["site-01"],
  SCENARIO_2_INSIDER_MISUSE: ["site-02"],
  SCENARIO_3_COORDINATED_CAMPAIGN: ["site-01", "site-02", "site-03"],
  SCENARIO_4_BENIGN_MAINTENANCE: ["site-02"],
  SCENARIO_5_DISCONNECTED_OPERATION: ["site-03"],
}

export function DashboardShell() {
  const { data: incidents } = useIncidents()
  const { data: metrics } = useMetrics()

  const [selectedIncident, setSelectedIncident] = useState<string | null>(null)
  const [site, setSite] = useState<string>(ALL_SITES)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [activeTab, setActiveTab] = useState<"overview" | "investigation" | "topology" | "analytics">("overview")
  const [graphMode, setGraphMode] = useState<"attack-path" | "blast-radius">("attack-path")
  const [sevFilter, setSevFilter] = useState<"ALL" | "CRITICAL" | "ELEVATED" | "NOMINAL">("ALL")
  const [sourceFilter, setSourceFilter] = useState<"ALL" | "LIVE" | "DEMO">("ALL")
  const [searchQuery, setSearchQuery] = useState("")
  const [ingestOpen, setIngestOpen] = useState(false)

  // Blast radius data state for dashboard topology view
  const [blastData, setBlastData] = useState<BlastRadiusResponse | null>(null)
  const [blastLoading, setBlastLoading] = useState(false)
  const [selectedHostIdx, setSelectedHostIdx] = useState(0)

  // Auto-select the highest-risk incident once loaded
  useEffect(() => {
    if (!selectedIncident && incidents && incidents.length > 0) {
      const top = [...incidents].sort((a, b) => b.risk_score - a.risk_score)[0]
      setSelectedIncident(top.incident_id)
    }
  }, [incidents, selectedIncident])

  // Fetch blast radius when switching to blast radius mode or selecting incident
  useEffect(() => {
    if (graphMode !== "blast-radius" || !selectedIncident) return
    setBlastLoading(true)
    getBlastRadius(selectedIncident)
      .then((res) => {
        setBlastData(res)
        if (res.hosts.length > 1) {
          const maxIdx = res.hosts.reduce(
            (best, h, i) => (h.score > res.hosts[best].score ? i : best),
            0,
          )
          setSelectedHostIdx(maxIdx)
        } else {
          setSelectedHostIdx(0)
        }
      })
      .catch(() => setBlastData(null))
      .finally(() => setBlastLoading(false))
  }, [graphMode, selectedIncident])

  const { data: incident } = useIncident(selectedIncident)

  const sites = ["site-01", "site-02", "site-03"]

  // Filtered incidents based on active site, search, severity, and source filters
  const filteredIncidents = useMemo(() => {
    let list = incidents ?? []
    if (site !== ALL_SITES) {
      list = list.filter((i) => {
        const mapped = SCENARIO_SITE_MAP[i.scenario_id] ?? ["site-01"]
        return mapped.includes(site)
      })
    }
    if (sourceFilter !== "ALL") {
      list = list.filter((i) => {
        if (sourceFilter === "LIVE") return i.source === "live"
        if (sourceFilter === "DEMO") return i.source !== "live"
        return true
      })
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      list = list.filter(
        (i) => i.title.toLowerCase().includes(q) || i.incident_id.toLowerCase().includes(q),
      )
    }
    if (sevFilter !== "ALL") {
      list = list.filter((i) => {
        const tone = riskTone(i.risk_score)
        if (sevFilter === "CRITICAL") return tone === "critical"
        if (sevFilter === "ELEVATED") return tone === "high" || tone === "medium"
        if (sevFilter === "NOMINAL") return tone === "low"
        return true
      })
    }
    return list
  }, [incidents, site, sourceFilter, searchQuery, sevFilter])

  // Counts for severity chips
  const sevCounts = useMemo(() => {
    const list = incidents ?? []
    const crit = list.filter((i) => riskTone(i.risk_score) === "critical").length
    const elev = list.filter((i) => {
      const t = riskTone(i.risk_score)
      return t === "high" || t === "medium"
    }).length
    const nom = list.filter((i) => riskTone(i.risk_score) === "low").length
    return { all: list.length, crit, elev, nom }
  }, [incidents])

  // Counts for source chips
  const sourceCounts = useMemo(() => {
    const list = incidents ?? []
    const live = list.filter((i) => i.source === "live").length
    const demo = list.filter((i) => i.source !== "live").length
    return { all: list.length, live, demo }
  }, [incidents])

  const activeTarget =
    (incident?.entity_ids ?? []).find((e) => e.startsWith("target_host:"))?.split(":")[1] ??
    (incident?.entity_ids ?? [])[0]?.split(":")[1] ??
    "synthetic-target"

  const selectedHost: BlastRadiusHostResult | null =
    blastData?.hosts[selectedHostIdx] ?? null

  const [utcTime, setUtcTime] = useState("--:--:--")

  useEffect(() => {
    const update = () => setUtcTime(new Date().toISOString().substring(11, 19))
    update()
    const timer = setInterval(update, 1000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e1e2ec]">
      {/* ─── Stitch Deep Space HUD Top Bar ─── */}
      <header
        className="sticky top-0 z-40 border-b border-[rgba(0,240,255,0.18)] bg-[#0c1222]/90 backdrop-blur-md"
        style={{
          boxShadow: "0 4px 20px -2px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.06)",
        }}
      >
        <div className="mx-auto flex max-w-[1700px] flex-wrap items-center justify-between gap-y-2 px-4 py-2">
          {/* Left Brand & Mission Title */}
          <div className="flex items-center gap-3">
            <div
              className="flex h-8 w-8 items-center justify-center rounded border border-[rgba(0,240,255,0.4)]"
              style={{
                background: "radial-gradient(circle, rgba(0,240,255,0.2) 0%, rgba(12,18,34,0.8) 100%)",
                boxShadow: "0 0 12px rgba(0,240,255,0.3)",
              }}
            >
              <Shield className="h-4 w-4 text-[#00f0ff]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold tracking-widest text-[#00f0ff]">
                  RAKSHAK-AI
                </span>
                <span className="font-mono text-[9px] text-muted-foreground">//</span>
                <span className="font-mono text-[9px] font-semibold text-[#00e5a3] tracking-wider">
                  LIVE SEC//OPS
                </span>
              </div>
              <p className="font-mono text-[9px] text-[#849495] tracking-tight">
                MISSION-AWARE CYBER DEFENCE SOC
              </p>
            </div>
          </div>

          {/* Center Tactical View Tabs */}
          <nav className="flex items-center gap-1">
            <NavTab
              active={activeTab === "overview"}
              onClick={() => setActiveTab("overview")}
              label="OVERVIEW / TRIAGE"
            />
            <NavTab
              active={activeTab === "investigation"}
              onClick={() => {
                setActiveTab("investigation")
                setGraphMode("attack-path")
              }}
              label="INCIDENT INVESTIGATION"
            />
            <NavTab
              active={activeTab === "topology"}
              onClick={() => {
                setActiveTab("topology")
                setGraphMode("blast-radius")
              }}
              label="TOPOLOGY // BLAST RADIUS"
            />
            <NavTab
              active={activeTab === "analytics"}
              onClick={() => setActiveTab("analytics")}
              label="METRICS & ANALYTICS"
            />
          </nav>

          {/* Right Status Block */}
          <div className="flex items-center gap-4">
            {/* Functional Site Selector */}
            <div className="flex items-center gap-1.5 rounded border border-[rgba(0,240,255,0.2)] bg-[#05070d]/80 px-2 py-0.5">
              <span className="font-mono text-[9px] uppercase tracking-wider text-[#849495]">SITE:</span>
              <Select value={site} onValueChange={(v) => setSite(v ?? ALL_SITES)}>
                <SelectTrigger className="h-6 border-0 bg-transparent p-0 font-mono text-[11px] font-semibold text-[#00f0ff] focus:ring-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-[rgba(0,240,255,0.2)] bg-[#0c1222] font-mono text-xs text-[#e1e2ec]">
                  <SelectItem value={ALL_SITES}>ALL SITES</SelectItem>
                  {sites.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s.toUpperCase()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Threat Level Indicator */}
            <div className="hidden sm:flex items-center gap-1.5 rounded border border-[rgba(255,0,85,0.3)] bg-[rgba(255,0,85,0.08)] px-2.5 py-1">
              <Flame className="h-3 w-3 text-[#ff0055]" />
              <span className="font-mono text-[10px] font-bold tracking-wider text-[#ff0055]">
                THREAT ELEVATION: {(metrics?.average_risk ?? 72).toFixed(1)}%
              </span>
            </div>

            {/* UTC Clock */}
            <div className="hidden lg:flex items-center gap-1 font-mono text-[10px] text-[#849495]">
              <Clock className="h-3 w-3" />
              <span>{utcTime} UTC</span>
            </div>

            {/* Ingest Logs Action */}
            <Button
              size="sm"
              onClick={() => setIngestOpen(true)}
              className="h-6 gap-1 bg-[rgba(0,240,255,0.12)] hover:bg-[rgba(0,240,255,0.22)] text-[#00f0ff] border border-[rgba(0,240,255,0.35)] font-mono text-[10px] font-bold tracking-wider"
            >
              <Upload className="h-3 w-3" />
              <span className="hidden sm:inline">INGEST LOGS</span>
            </Button>

            <ConnectionStatus />
          </div>
        </div>
      </header>

      {/* ─── Main Cockpit Layout ─── */}
      <div className="mx-auto flex max-w-[1700px]">
        {/* Left Vertical HUD Rail */}
        <aside
          className="hidden xl:flex w-52 shrink-0 flex-col justify-between border-r border-[rgba(0,240,255,0.14)] bg-[#060911]/80 p-3"
          style={{ minHeight: "calc(100vh - 49px)" }}
        >
          <div className="space-y-4">
            <div className="border-b border-[rgba(0,240,255,0.12)] pb-2">
              <span className="font-mono text-[9px] uppercase tracking-widest text-[#849495]">
                TACTICAL COCKPIT
              </span>
            </div>

            <nav className="space-y-1">
              <RailButton
                active={activeTab === "overview"}
                onClick={() => setActiveTab("overview")}
                icon={<Activity className="h-3.5 w-3.5" />}
                label="Overview & Triage"
                badge={`${sevCounts.crit} CRIT`}
                badgeTone="critical"
              />
              <RailButton
                active={activeTab === "investigation"}
                onClick={() => {
                  setActiveTab("investigation")
                  setGraphMode("attack-path")
                }}
                icon={<Crosshair className="h-3.5 w-3.5" />}
                label="Investigation"
                badge={selectedIncident ? selectedIncident.substring(0, 7) : "NONE"}
                badgeTone="primary"
              />
              <RailButton
                active={activeTab === "topology"}
                onClick={() => {
                  setActiveTab("topology")
                  setGraphMode("blast-radius")
                }}
                icon={<Radio className="h-3.5 w-3.5" />}
                label="Blast Radius"
                badge="ACTIVE"
                badgeTone="violet"
              />
              <RailButton
                active={activeTab === "analytics"}
                onClick={() => setActiveTab("analytics")}
                icon={<Cpu className="h-3.5 w-3.5" />}
                label="Analytics & Feeds"
                badge="LIVE"
                badgeTone="emerald"
              />
              <RailButton
                active={false}
                onClick={() => setIngestOpen(true)}
                icon={<Upload className="h-3.5 w-3.5 text-[#00f0ff]" />}
                label="Ingest Forensic Logs"
                badge={`${sourceCounts.live} LIVE`}
                badgeTone="primary"
              />
            </nav>
          </div>

          {/* Perimeter & Quarantine Status Box */}
          <div className="rounded border border-[rgba(0,240,255,0.15)] bg-[#0c1222]/70 p-2.5 font-mono text-[10px]">
            <div className="flex items-center justify-between text-muted-foreground mb-1">
              <span>PERIMETER</span>
              <span className="text-[#00e5a3] font-bold">[ LOCKED ]</span>
            </div>
            <div className="flex items-center justify-between text-muted-foreground">
              <span>QUARANTINE</span>
              <span className="text-[#00f0ff] font-bold">84% ENFORCED</span>
            </div>
            <div className="mt-1.5 h-1 w-full rounded bg-white/10 overflow-hidden">
              <div className="h-full bg-gradient-to-r from-[#00e5a3] to-[#00f0ff] w-[84%]" />
            </div>
          </div>
        </aside>

        {/* ─── Main Viewport ─── */}
        <main className="flex-1 space-y-4 p-4 min-w-0">
          {/* Top HUD Metrics Ribbon */}
          <RiskSummary />

          {/* Filter, Search & Quick Actions Toolbar */}
          <div
            className="flex flex-wrap items-center justify-between gap-2 rounded-md p-2.5"
            style={{
              background: "rgba(12, 18, 34, 0.75)",
              border: "1px solid rgba(0, 240, 255, 0.18)",
              backdropFilter: "blur(16px)",
            }}
          >
            {/* Search Input */}
            <div className="flex items-center gap-2 rounded border border-[rgba(0,240,255,0.18)] bg-[#05070d]/90 px-2.5 py-1 text-xs">
              <Search className="h-3.5 w-3.5 text-[#00f0ff]" />
              <input
                type="text"
                placeholder="SEARCH INCIDENTS (CTRL+K)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-48 bg-transparent font-mono text-xs text-[#e1e2ec] placeholder-[#849495] outline-none"
              />
            </div>

            {/* Severity Filter Chips */}
            <div className="flex items-center gap-1.5 flex-wrap">
              <FilterChip
                active={sevFilter === "ALL"}
                onClick={() => setSevFilter("ALL")}
                label={`ALL [${sevCounts.all}]`}
              />
              <FilterChip
                active={sevFilter === "CRITICAL"}
                onClick={() => setSevFilter("CRITICAL")}
                label={`CRITICAL [${sevCounts.crit}]`}
                color="#ff0055"
              />
              <FilterChip
                active={sevFilter === "ELEVATED"}
                onClick={() => setSevFilter("ELEVATED")}
                label={`ELEVATED [${sevCounts.elev}]`}
                color="#ffb020"
              />
              <FilterChip
                active={sevFilter === "NOMINAL"}
                onClick={() => setSevFilter("NOMINAL")}
                label={`NOMINAL [${sevCounts.nom}]`}
                color="#00e5a3"
              />
            </div>

            {/* Source Filter Chips */}
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="font-mono text-[9px] uppercase tracking-wider text-[#849495]">SOURCE:</span>
              <FilterChip
                active={sourceFilter === "ALL"}
                onClick={() => setSourceFilter("ALL")}
                label="ALL"
              />
              <FilterChip
                active={sourceFilter === "LIVE"}
                onClick={() => setSourceFilter("LIVE")}
                label={`LIVE [${sourceCounts.live}]`}
                color="#00f0ff"
              />
              <FilterChip
                active={sourceFilter === "DEMO"}
                onClick={() => setSourceFilter("DEMO")}
                label={`DEMO [${sourceCounts.demo}]`}
                color="#ffb020"
              />
            </div>

            {/* View Mode & Quick Actions */}
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] text-[#849495] hidden md:inline">
                VIEW:
              </span>
              <button
                onClick={() => setGraphMode("attack-path")}
                className={`rounded px-2.5 py-1 font-mono text-[11px] font-semibold transition-all ${
                  graphMode === "attack-path"
                    ? "border border-[#00f0ff] bg-[#00f0ff]/15 text-[#00f0ff] shadow-[0_0_10px_rgba(0,240,255,0.3)]"
                    : "border border-transparent text-[#849495] hover:text-[#e1e2ec]"
                }`}
              >
                ATTACK PATH
              </button>
              <button
                onClick={() => setGraphMode("blast-radius")}
                className={`rounded px-2.5 py-1 font-mono text-[11px] font-semibold transition-all ${
                  graphMode === "blast-radius"
                    ? "border border-[#a855f7] bg-[#a855f7]/15 text-[#a855f7] shadow-[0_0_10px_rgba(168,85,247,0.3)]"
                    : "border border-transparent text-[#849495] hover:text-[#e1e2ec]"
                }`}
              >
                BLAST RADIUS
              </button>
            </div>
          </div>

          {/* ─── WORKSPACE PANELS ─── */}
          {activeTab === "overview" && (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-[340px_1fr]">
              <div className="space-y-4">
                <TacticalIncidentList
                  incidents={filteredIncidents}
                  selectedId={selectedIncident}
                  onSelect={(id) => {
                    setSelectedIncident(id)
                    setSelectedNode(null)
                  }}
                />
                <ScenarioControls onReplay={setSelectedIncident} />
              </div>
              <div className="space-y-4">
                <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                  <SeverityChart metrics={metrics} />
                  <RiskHistogram metrics={metrics} />
                </div>
                <CampaignView siteFilter={site} />
              </div>
            </div>
          )}

          {(activeTab === "investigation" || activeTab === "topology") && (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-[340px_1fr]">
              {/* Left Column: Tactical Incident List + Scenario Controls */}
              <div className="space-y-4">
                <TacticalIncidentList
                  incidents={filteredIncidents}
                  selectedId={selectedIncident}
                  onSelect={(id) => {
                    setSelectedIncident(id)
                    setSelectedNode(null)
                  }}
                />
                <ScenarioControls onReplay={setSelectedIncident} />
              </div>

              {/* Right Column: Tactical Graph Canvas (Attack Path or Blast Radius) */}
              <div className="space-y-4">
                <div
                  className="flex flex-col gap-2 overflow-hidden rounded-md p-4"
                  style={{
                    background: "rgba(12, 18, 34, 0.75)",
                    border: "1px solid rgba(0, 240, 255, 0.18)",
                    backdropFilter: "blur(16px)",
                    boxShadow: "0 0 20px -4px rgba(0, 240, 255, 0.08), inset 0 1px 0 0 rgba(255, 255, 255, 0.06)",
                  }}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[rgba(0,240,255,0.12)] pb-2.5">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold uppercase tracking-wider text-[#00f0ff]">
                          {graphMode === "attack-path"
                            ? "COMPROMISE GRAPH // ATTACK PATHWAY"
                            : "TOPOLOGY MATRIX // BLAST RADIUS CONTAINMENT"}
                        </span>
                        {incident ? (
                          <span className="font-mono text-[10px] text-muted-foreground">
                            [{incident.incident_id}]
                          </span>
                        ) : null}
                      </div>
                      <p className="mt-0.5 font-mono text-[11px] text-[#849495]">
                        {incident
                          ? incident.title
                          : "Deterministic graph — reconstructed from normalized OCSF security events."}
                      </p>
                    </div>

                    {incident ? (
                      <Link
                        href={`/incidents/${incident.incident_id}`}
                        className="flex items-center gap-1 rounded border border-[rgba(0,240,255,0.3)] bg-[#00f0ff]/10 px-2.5 py-1 font-mono text-xs text-[#00f0ff] transition-all hover:bg-[#00f0ff]/20 hover:shadow-[0_0_12px_rgba(0,240,255,0.3)]"
                      >
                        Open full incident <ExternalLink className="h-3 w-3" />
                      </Link>
                    ) : null}
                  </div>

                  {/* Graph Rendering Area */}
                  {graphMode === "attack-path" ? (
                    <>
                      <div className="h-[460px]">
                        <AttackPathGraph graph={incident?.graph} onSelectNode={setSelectedNode} />
                      </div>
                      {selectedNode ? (
                        <NodeEvidence node={selectedNode} />
                      ) : (
                        <div className="flex items-center justify-between font-mono text-[10px] text-[#849495] pt-1">
                          <span>Click any graph node to inspect forensic evidence refs.</span>
                          <span>Dagre Flow // Left-to-Right layout</span>
                        </div>
                      )}
                    </>
                  ) : (
                    /* Blast Radius Network View on Dashboard */
                    <div className="flex flex-col gap-3">
                      {blastLoading && (
                        <div className="flex h-[460px] items-center justify-center font-mono text-xs text-[#00f0ff]">
                          Computing topological blast radius...
                        </div>
                      )}

                      {!blastLoading && blastData && (
                        <>
                          {/* Multiple hosts selector if applicable */}
                          {blastData.hosts.length > 1 && (
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-xs text-muted-foreground">
                                TARGET HOST:
                              </span>
                              {blastData.hosts.map((h, i) => (
                                <button
                                  key={h.host}
                                  onClick={() => setSelectedHostIdx(i)}
                                  className="rounded px-2 py-0.5 font-mono text-xs transition-colors"
                                  style={{
                                    background:
                                      i === selectedHostIdx
                                        ? "rgba(0,240,255,0.15)"
                                        : "rgba(255,255,255,0.04)",
                                    border:
                                      i === selectedHostIdx
                                        ? "1px solid rgba(0,240,255,0.45)"
                                        : "1px solid rgba(255,255,255,0.1)",
                                    color: i === selectedHostIdx ? "#00f0ff" : "rgba(185,202,203,0.7)",
                                  }}
                                >
                                  {h.host} ({h.score.toFixed(1)})
                                </button>
                              ))}
                            </div>
                          )}

                          {selectedHost ? (
                            <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_280px]">
                              <div className="h-[460px]">
                                <BlastRadiusNetworkView result={selectedHost} width={800} height={460} />
                              </div>
                              <div>
                                <BlastRadiusReadout result={selectedHost} />
                              </div>
                            </div>
                          ) : (
                            <div className="flex h-[400px] items-center justify-center font-mono text-xs text-muted-foreground">
                              No blast radius data for this incident.
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  )}
                </div>
                
                {/* Copilot & Actions for Investigation */}
                <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                  <AIInsightPanel incidentId={selectedIncident} initial={incident?.analysis} key={selectedIncident} />
                  <div className="space-y-4">
                    <ResponseActions incidentId={selectedIncident} target={activeTarget} />
                    {incident ? <IncidentTimeline timeline={incident.timeline} /> : null}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "analytics" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                <TelemetryFeed siteFilter={site} />
                <TechniqueChart metrics={metrics} />
                <EntityRiskTable metrics={metrics} />
              </div>
            </div>
          )}

          {/* ─── Stitch Live Telemetry Mesh Footer Bar ─── */}
          <footer
            className="mt-6 flex flex-wrap items-center justify-between gap-3 rounded-md px-4 py-3 font-mono text-[11px]"
            style={{
              background: "rgba(12, 18, 34, 0.75)",
              border: "1px solid rgba(0, 240, 255, 0.18)",
              backdropFilter: "blur(16px)",
            }}
          >
            <div className="flex items-center gap-2.5">
              <span className="flex h-2 w-2 rounded-full bg-[#00e5a3] animate-pulse" />
              <span className="font-bold text-[#e1e2ec]">LIVE HONEYPOT & SENSOR MESH</span>
              <span className="text-[#849495] hidden md:inline">
                // Global Telemetry Mesh active across 48 AWS/GCP regions and 32 on-prem datacenters <span className="text-[#ffb020] ml-2">[DECORATIVE]</span>
              </span>
            </div>

            <div className="flex items-center gap-4 text-[#849495] flex-wrap">
              <span>PROVENANCE: <strong className="text-[#00e5a3]">LIVE ({metrics?.provenance_breakdown?.events?.live ?? 0}) / DEMO ({metrics?.provenance_breakdown?.events?.demo ?? 0})</strong></span>
              <span>SIEM INGEST: <strong className="text-[#00e5a3]">SYNCHRONIZED</strong></span>
              <span>SOAR QUEUE: <strong className="text-[#ffb020]">RUNNING</strong></span>
            </div>
          </footer>
        </main>
      </div>

      <LogIngestionModal
        open={ingestOpen}
        onClose={() => setIngestOpen(false)}
        onSelectIncident={(id) => {
          setSelectedIncident(id)
          setActiveTab("investigation")
        }}
      />
    </div>
  )
}

// ─── Subcomponents with Stitch Deep Space HUD Styling ───

function NavTab({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 font-mono text-xs font-semibold tracking-wider transition-all relative ${
        active
          ? "text-[#00f0ff]"
          : "text-[#849495] hover:text-[#e1e2ec]"
      }`}
    >
      {label}
      {active && (
        <span
          className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#00f0ff]"
          style={{ boxShadow: "0 0 8px #00f0ff" }}
        />
      )}
    </button>
  )
}

function RailButton({
  active,
  onClick,
  icon,
  label,
  badge,
  badgeTone = "primary",
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  label: string
  badge?: string
  badgeTone?: "primary" | "critical" | "violet" | "emerald"
}) {
  const toneBg = {
    primary: "rgba(0, 240, 255, 0.15)",
    critical: "rgba(255, 0, 85, 0.15)",
    violet: "rgba(168, 85, 247, 0.15)",
    emerald: "rgba(0, 229, 163, 0.15)",
  }[badgeTone]

  const toneColor = {
    primary: "#00f0ff",
    critical: "#ff0055",
    violet: "#a855f7",
    emerald: "#00e5a3",
  }[badgeTone]

  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center justify-between rounded px-2.5 py-2 font-mono text-xs transition-all text-left ${
        active
          ? "border border-[rgba(0,240,255,0.4)] bg-[#00f0ff]/10 text-[#00f0ff] shadow-[0_0_12px_rgba(0,240,255,0.15)]"
          : "border border-transparent text-[#849495] hover:bg-white/5 hover:text-[#e1e2ec]"
      }`}
    >
      <div className="flex items-center gap-2 truncate">
        {icon}
        <span className="truncate">{label}</span>
      </div>
      {badge ? (
        <span
          className="rounded px-1.5 py-0.5 font-mono text-[9px] font-bold"
          style={{ background: toneBg, color: toneColor }}
        >
          {badge}
        </span>
      ) : null}
    </button>
  )
}

function FilterChip({
  active,
  onClick,
  label,
  color,
}: {
  active: boolean
  onClick: () => void
  label: string
  color?: string
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded px-2.5 py-1 font-mono text-[10px] font-bold tracking-wider transition-all ${
        active
          ? "border bg-white/10 text-white"
          : "border border-transparent text-[#849495] hover:text-[#e1e2ec] hover:bg-white/5"
      }`}
      style={{
        borderColor: active ? (color ?? "#00f0ff") : undefined,
        color: active ? (color ?? "#00f0ff") : undefined,
        boxShadow: active && color ? `0 0 8px ${color}40` : undefined,
      }}
    >
      {label}
    </button>
  )
}

function TacticalIncidentList({
  incidents,
  selectedId,
  onSelect,
}: {
  incidents: {
    incident_id: string
    title: string
    risk_score: number
    status: string
    scenario_id: string
    created_at: string
    source?: string
  }[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <div
      className="flex flex-col gap-2 rounded-md p-3.5"
      style={{
        background: "rgba(12, 18, 34, 0.75)",
        border: "1px solid rgba(0, 240, 255, 0.18)",
        backdropFilter: "blur(16px)",
      }}
    >
      <div className="flex items-center justify-between border-b border-[rgba(0,240,255,0.12)] pb-2">
        <h3 className="font-mono text-xs font-bold uppercase tracking-widest text-[#00f0ff]">
          ACTIVE INCIDENTS ({incidents.length})
        </h3>
        <span className="font-mono text-[10px] text-[#849495]">TRIAGE QUEUE</span>
      </div>

      {incidents.length === 0 ? (
        <p className="py-6 text-center font-mono text-xs text-muted-foreground">
          No incidents match current filter.
        </p>
      ) : (
        <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1 rakshak-scroll">
          {[...incidents]
            .sort((a, b) => b.risk_score - a.risk_score)
            .map((i) => {
              const tone = riskTone(i.risk_score)
              const active = i.incident_id === selectedId
              const sevColor = SEVERITY_COLOR[tone]
              const sevTag = tone === "critical" ? "CRITICAL // SEV-1" : tone === "high" ? "ELEVATED // THREAT" : "NOMINAL // RECON"

              return (
                <div
                  key={i.incident_id}
                  onClick={() => onSelect(i.incident_id)}
                  className={`group cursor-pointer rounded border p-2.5 transition-all text-left ${
                    active
                      ? "border-[#00f0ff] bg-[#00f0ff]/10 shadow-[0_0_14px_rgba(0,240,255,0.2)]"
                      : "border-[rgba(0,240,255,0.12)] bg-[#05070d]/60 hover:border-[rgba(0,240,255,0.25)] hover:bg-[#0c1222]/80"
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span
                      className="font-mono text-[9px] font-bold tracking-wider"
                      style={{ color: sevColor }}
                    >
                      {sevTag}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[10px] text-[#849495]">
                        {i.incident_id}
                      </span>
                      <span
                        className="rounded px-1.5 py-0.2 font-mono text-[10px] font-bold"
                        style={{
                          color: sevColor,
                          background: `color-mix(in srgb, ${sevColor} 15%, transparent)`,
                          border: `1px solid ${sevColor}40`,
                        }}
                      >
                        {i.risk_score.toFixed(0)}
                      </span>
                    </div>
                  </div>

                  <p className="font-mono text-xs font-semibold text-[#e1e2ec] line-clamp-1 group-hover:text-[#00f0ff] transition-colors">
                    {i.title}
                  </p>

                  <div className="mt-2 flex items-center justify-between font-mono text-[9px] text-[#849495]">
                    <div className="flex items-center gap-1.5">
                      {i.source === "live" ? (
                        <span className="rounded px-1.5 py-0.2 font-mono text-[8px] font-bold border border-[#00f0ff] bg-[#00f0ff]/15 text-[#00f0ff]">
                          LIVE
                        </span>
                      ) : (
                        <span className="rounded px-1.5 py-0.2 font-mono text-[8px] font-bold border border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffb020]">
                          DEMO
                        </span>
                      )}
                      <span>{i.scenario_id ? i.scenario_id.replace("SCENARIO_", "S") : "INGEST"}</span>
                    </div>
                    <span className="uppercase text-[#00e5a3]">{i.status}</span>
                  </div>
                </div>
              )
            })}
        </div>
      )}
    </div>
  )
}

function NodeEvidence({ node }: { node: GraphNode }) {
  return (
    <div className="rounded border border-[rgba(0,240,255,0.2)] bg-[#05070d]/90 p-2.5 font-mono text-xs">
      <div className="flex items-center gap-2">
        <span className="rounded bg-[#00f0ff]/15 px-1.5 py-0.5 text-[9px] font-bold text-[#00f0ff]">
          {node.data.entity_type.toUpperCase()}
        </span>
        <span className="font-bold text-[#e1e2ec]">{node.data.label}</span>
        <span
          className="ml-auto rounded px-1.5 py-0.5 text-[9px] font-bold uppercase"
          style={{
            backgroundColor: `color-mix(in srgb, ${SEVERITY_COLOR[node.data.severity]} 20%, transparent)`,
            color: SEVERITY_COLOR[node.data.severity],
            border: `1px solid ${SEVERITY_COLOR[node.data.severity]}40`,
          }}
        >
          {node.data.severity}
        </span>
      </div>
      <p className="mt-1.5 text-[10px] text-[#849495]">
        EVIDENCE REFS: {node.data.evidence_event_ids.join(", ") || "none"}
      </p>
    </div>
  )
}

function CampaignView({ siteFilter }: { siteFilter: string }) {
  const { data: metrics } = useMetrics()
  const allCampaigns = metrics?.cross_site_campaigns ?? []

  const campaigns = useMemo(() => {
    if (siteFilter === ALL_SITES) return allCampaigns
    return allCampaigns.filter((c) => c.sites.includes(siteFilter))
  }, [allCampaigns, siteFilter])

  if (campaigns.length === 0) return null

  return (
    <div
      className="flex flex-col gap-2 rounded-md p-4"
      style={{
        background: "rgba(12, 18, 34, 0.75)",
        border: "1px solid rgba(0, 240, 255, 0.18)",
        backdropFilter: "blur(16px)",
      }}
    >
      <div className="flex items-center justify-between border-b border-[rgba(0,240,255,0.12)] pb-2">
        <h3 className="font-mono text-xs font-bold uppercase tracking-widest text-[#00f0ff]">
          CROSS-SITE CAMPAIGN CORRELATION
        </h3>
        <span className="font-mono text-[10px] text-[#849495]">MULTI-SITE THREAT CLUSTER</span>
      </div>

      <div className="space-y-2">
        {campaigns.map((c) => (
          <Link
            key={c.incident_id}
            href={`/incidents/${c.incident_id}`}
            className="flex items-center justify-between gap-3 rounded border border-[rgba(255,0,85,0.3)] bg-[rgba(255,0,85,0.06)] p-3 transition-all hover:bg-[rgba(255,0,85,0.12)] hover:border-[rgba(255,0,85,0.5)]"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[9px] font-bold text-[#ff0055]">
                  CAMPAIGN DETECTED
                </span>
                <span className="font-mono text-[9px] text-[#849495]">
                  [{c.incident_id}]
                </span>
              </div>
              <p className="font-mono text-xs font-semibold text-[#e1e2ec] mt-0.5 truncate">
                {c.title}
              </p>
              <p className="mt-1 font-mono text-[10px] text-[#849495]">
                CORRELATED SITES: {c.sites.join(", ")}
              </p>
            </div>
            <div className="text-right">
              <span className="font-mono text-sm font-bold text-[#ff0055]">
                {c.risk_score.toFixed(0)} RISK
              </span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  )
}
