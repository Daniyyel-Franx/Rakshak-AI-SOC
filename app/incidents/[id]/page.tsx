"use client"

import { use, useState, useEffect, useRef } from "react"
import Link from "next/link"
import { ArrowLeft, Shield, Activity, Crosshair } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { AttackPathGraph } from "@/components/AttackPathGraph"
import { BlastRadiusNetworkView } from "@/components/BlastRadiusNetworkView"
import { BlastRadiusReadout } from "@/components/BlastRadiusReadout"
import { IncidentTimeline } from "@/components/IncidentTimeline"
import { AIInsightPanel } from "@/components/AIInsightPanel"
import { ResponseActions } from "@/components/ResponseActions"
import { ConnectionStatus } from "@/components/ConnectionStatus"
import { useIncident } from "@/lib/hooks"
import { getBlastRadius } from "@/lib/api"
import { riskTone, SEVERITY_COLOR } from "@/lib/ui"
import type { BlastRadiusResponse, BlastRadiusHostResult } from "@/lib/types"

type Tab = "attack-path" | "blast-radius"

export default function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const { data: incident, isLoading, error } = useIncident(id)

  const [activeTab, setActiveTab] = useState<Tab>("attack-path")
  const [blastData, setBlastData] = useState<BlastRadiusResponse | null>(null)
  const [blastLoading, setBlastLoading] = useState(false)
  const [blastError, setBlastError] = useState<string | null>(null)
  const [selectedHostIdx, setSelectedHostIdx] = useState(0)
  const hasFetchedBlast = useRef(false)

  const target =
    (incident?.entity_ids ?? []).find((e) => e.startsWith("target_host:"))?.split(":")[1] ??
    "synthetic-target"

  // Fetch blast radius when the tab is first opened
  useEffect(() => {
    if (activeTab !== "blast-radius" || hasFetchedBlast.current || !incident) return
    hasFetchedBlast.current = true
    setBlastLoading(true)
    setBlastError(null)
    getBlastRadius(id)
      .then((data) => {
        setBlastData(data)
        // Default to highest-scoring host
        if (data.hosts.length > 1) {
          const maxIdx = data.hosts.reduce(
            (best, h, i) => (h.score > data.hosts[best].score ? i : best),
            0,
          )
          setSelectedHostIdx(maxIdx)
        }
      })
      .catch(() => setBlastError("Failed to load blast radius data."))
      .finally(() => setBlastLoading(false))
  }, [activeTab, incident, id])

  const selectedHost: BlastRadiusHostResult | null =
    blastData?.hosts[selectedHostIdx] ?? null

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-30 border-b border-border bg-sidebar/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1400px] items-center gap-4 px-4 py-2.5">
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Dashboard
          </Link>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-[var(--chart-1)]" />
            <span className="text-sm font-semibold">Rakshak-AI</span>
          </div>
          <div className="ml-auto">
            <ConnectionStatus />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1400px] space-y-4 px-4 py-4">
        {isLoading && !incident ? (
          <div className="space-y-4">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-[440px] w-full" />
          </div>
        ) : error || !incident ? (
          <Card className="p-6 text-center text-sm text-[var(--chart-2)]">
            Incident not found or backend unavailable. Return to the{" "}
            <Link href="/dashboard" className="text-[var(--chart-1)] underline">
              dashboard
            </Link>
            .
          </Card>
        ) : (
          <>
            {/* ── Incident header card ── */}
            <Card className="flex flex-wrap items-center justify-between gap-3 p-4">
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-pretty text-base font-semibold">{incident.title}</h1>
                  <Badge variant="outline" className="text-[9px]">
                    {incident.status}
                  </Badge>
                  {incident.source === "live" ? (
                    <Badge variant="outline" className="text-[9px] border-[#00f0ff] text-[#00f0ff] bg-[#00f0ff]/10">
                      LIVE FORENSIC
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-[9px] border-[#ffb020] text-[#ffb020] bg-[#ffb020]/10">
                      DEMO SCENARIO
                    </Badge>
                  )}
                </div>
                <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                  {incident.incident_id} · {incident.scenario_id} · mission impact:{" "}
                  {incident.mission_impact}
                </p>
              </div>
              <div className="flex items-center gap-4">
                <Metric
                  label="Risk"
                  value={incident.risk_score.toFixed(0)}
                  color={SEVERITY_COLOR[riskTone(incident.risk_score)]}
                />
                <Metric
                  label="Confidence"
                  value={`${Math.round(incident.confidence * 100)}%`}
                  color="var(--chart-2)"
                />
                <Metric label="Findings" value={String(incident.finding_count)} color="var(--chart-1)" />
              </div>
            </Card>

            {/* ── Tab selector ── */}
            <div className="flex items-center gap-1 rounded-md border border-border p-0.5 w-fit">
              <TabButton
                active={activeTab === "attack-path"}
                onClick={() => setActiveTab("attack-path")}
                icon={<Activity className="h-3.5 w-3.5" />}
                label="Attack Path"
              />
              <TabButton
                active={activeTab === "blast-radius"}
                onClick={() => setActiveTab("blast-radius")}
                icon={<Crosshair className="h-3.5 w-3.5" />}
                label="Blast Radius"
              />
            </div>

            {/* ── Attack Path panel ── */}
            {activeTab === "attack-path" && (
              <Card className="flex flex-col gap-2 p-4">
                <h2 className="text-sm font-semibold">Attack pathway</h2>
                <div className="h-[460px]">
                  <AttackPathGraph graph={incident.graph} />
                </div>
              </Card>
            )}

            {/* ── Blast Radius panel ── */}
            {activeTab === "blast-radius" && (
              <div className="flex flex-col gap-3">
                {blastLoading && (
                  <Skeleton className="h-[460px] w-full" />
                )}

                {blastError && (
                  <Card className="p-6 text-center text-sm text-[var(--chart-2)]">
                    {blastError}
                  </Card>
                )}

                {!blastLoading && !blastError && blastData && (
                  <>
                    {/* Host selector (only shown when multiple hosts) */}
                    {blastData.hosts.length > 1 && (
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className="text-xs text-muted-foreground"
                          style={{ fontFamily: "JetBrains Mono, monospace" }}
                        >
                          COMPROMISED HOST:
                        </span>
                        {blastData.hosts.map((h, i) => (
                          <button
                            key={h.host}
                            onClick={() => setSelectedHostIdx(i)}
                            className="rounded px-2 py-0.5 text-xs transition-colors"
                            style={{
                              fontFamily: "JetBrains Mono, monospace",
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
                            {h.host}
                            <span
                              style={{
                                marginLeft: 6,
                                color: i === selectedHostIdx ? "#00dbe9" : "rgba(185,202,203,0.4)",
                              }}
                            >
                              {h.score.toFixed(1)}
                            </span>
                          </button>
                        ))}
                      </div>
                    )}

                    {/* Empty hosts state */}
                    {blastData.hosts.length === 0 && (
                      <Card className="p-6 text-center text-sm text-muted-foreground">
                        No target hosts identified in this incident's attack graph.
                      </Card>
                    )}

                    {/* Main visualization + readout */}
                    {selectedHost && (
                      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_280px]">
                        <div className="h-[460px]">
                          <BlastRadiusNetworkView result={selectedHost} width={900} height={460} />
                        </div>
                        <div>
                          <BlastRadiusReadout result={selectedHost} />
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* ── Bottom panels (always visible) ── */}
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <AIInsightPanel incidentId={incident.incident_id} initial={incident.analysis} />
              </div>
              <div className="space-y-4">
                <ResponseActions incidentId={incident.incident_id} target={target} />
                <IncidentTimeline timeline={incident.timeline} />
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  )
}

function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  label: string
}) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors"
      style={{
        background: active ? "rgba(0,240,255,0.12)" : "transparent",
        color: active ? "#00f0ff" : "var(--muted-foreground)",
        border: active ? "1px solid rgba(0,240,255,0.30)" : "1px solid transparent",
      }}
    >
      {icon}
      {label}
    </button>
  )
}

function Metric({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="text-right">
      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="font-mono text-xl font-semibold" style={{ color }}>
        {value}
      </p>
    </div>
  )
}
