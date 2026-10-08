"use client"

import { Activity, AlertTriangle, ShieldAlert, Gauge, Zap, Inbox } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useMetrics } from "@/lib/hooks"
import { riskTone } from "@/lib/ui"
import type { LucideIcon } from "lucide-react"

function StatCard({
  label,
  value,
  icon: Icon,
  tone = "muted",
  badge,
  hint,
}: {
  label: string
  value: string | number
  icon: LucideIcon
  tone?: "muted" | "low" | "medium" | "high" | "critical" | "primary"
  badge?: string
  hint?: string
}) {
  const toneColor: Record<string, string> = {
    muted: "var(--muted-foreground)",
    primary: "var(--chart-1)",
    low: "var(--chart-4)",
    medium: "var(--chart-2)",
    high: "var(--chart-3)",
    critical: "var(--destructive)",
  }
  const color = toneColor[tone] ?? "var(--foreground)"

  return (
    <div
      className="flex flex-col justify-between gap-2 rounded-md p-3.5 transition-all"
      style={{
        background: "rgba(12, 18, 34, 0.75)",
        border: "1px solid rgba(0, 240, 255, 0.18)",
        backdropFilter: "blur(16px)",
        boxShadow: "0 0 16px -4px rgba(0, 240, 255, 0.08), inset 0 1px 0 0 rgba(255, 255, 255, 0.06)",
      }}
    >
      <div className="flex items-center justify-between gap-1.5">
        <span
          className="font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
          style={{ letterSpacing: "0.1em" }}
        >
          {label}
        </span>
        <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
      </div>
      <div className="flex items-baseline justify-between gap-2">
        <span
          className="font-mono text-2xl font-bold tracking-tight"
          style={{ color, textShadow: tone === "critical" || tone === "primary" ? `0 0 14px ${color}55` : undefined }}
        >
          {value}
        </span>
        {badge ? (
          <span
            className="rounded px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider"
            style={{
              color,
              background: `color-mix(in srgb, ${color} 15%, transparent)`,
              border: `1px solid color-mix(in srgb, ${color} 35%, transparent)`,
            }}
          >
            {badge}
          </span>
        ) : null}
      </div>
      {hint ? (
        <span className="font-mono text-[10px] text-muted-foreground truncate">{hint}</span>
      ) : null}
    </div>
  )
}

export function RiskSummary() {
  const { data: m, isLoading, error } = useMetrics()

  if (isLoading && !m) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-[104px] w-full" />
        ))}
      </div>
    )
  }

  if (error || !m) {
    return (
      <Card className="p-4 text-sm text-[var(--chart-2)]">
        Metrics unavailable — showing degraded state. Check the backend connection.
      </Card>
    )
  }

  const critCount = m.critical_incidents
  const avgRisk = m.average_risk
  const tone = riskTone(avgRisk)

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <StatCard
        label="Total Events"
        value={m.total_events.toLocaleString()}
        icon={Activity}
        tone="primary"
        badge="LIVE"
        hint="Telemetry Stream"
      />
      <StatCard
        label="Active Incidents"
        value={m.active_incidents}
        icon={AlertTriangle}
        tone={m.active_incidents > 0 ? "medium" : "muted"}
        badge={m.active_incidents > 0 ? "ALERT" : "STABLE"}
        hint={critCount > 0 ? `${critCount} Critical` : "Nominal"}
      />
      <StatCard
        label="Critical Breaches"
        value={critCount}
        icon={ShieldAlert}
        tone={critCount > 0 ? "critical" : "muted"}
        badge={critCount > 0 ? "SEV-1" : "CLEAR"}
        hint="Host Containment"
      />
      <StatCard
        label="Global Risk Index"
        value={avgRisk.toFixed(1)}
        icon={Gauge}
        tone={tone}
        badge={tone.toUpperCase()}
        hint="Calibrated Exposure"
      />
      <StatCard
        label="Triage Velocity"
        value={`${m.events_per_minute.toFixed(1)}/m`}
        icon={Zap}
        tone="primary"
        badge="ACTIVE"
        hint="Ingestion Rate"
      />
      <StatCard
        label="Queued Offline"
        value={m.queued_offline_events}
        icon={Inbox}
        tone={m.queued_offline_events > 0 ? "medium" : "muted"}
        badge={m.queued_offline_events > 0 ? "BUFFER" : "SYNC"}
        hint="Replay Buffer"
      />
    </div>
  )
}
