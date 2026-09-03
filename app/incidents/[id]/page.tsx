"use client"

import { use } from "react"
import Link from "next/link"
import { ArrowLeft, Shield } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { AttackPathGraph } from "@/components/AttackPathGraph"
import { IncidentTimeline } from "@/components/IncidentTimeline"
import { AIInsightPanel } from "@/components/AIInsightPanel"
import { ResponseActions } from "@/components/ResponseActions"
import { ConnectionStatus } from "@/components/ConnectionStatus"
import { useIncident } from "@/lib/hooks"
import { riskTone, SEVERITY_COLOR } from "@/lib/ui"

export default function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const { data: incident, isLoading, error } = useIncident(id)

  const target =
    (incident?.entity_ids ?? []).find((e) => e.startsWith("target_host:"))?.split(":")[1] ??
    "synthetic-target"

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
            <Card className="flex flex-wrap items-center justify-between gap-3 p-4">
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-pretty text-base font-semibold">{incident.title}</h1>
                  <Badge variant="outline" className="text-[9px]">
                    {incident.status}
                  </Badge>
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

            <Card className="flex flex-col gap-2 p-4">
              <h2 className="text-sm font-semibold">Attack pathway</h2>
              <div className="h-[460px]">
                <AttackPathGraph graph={incident.graph} />
              </div>
            </Card>

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
