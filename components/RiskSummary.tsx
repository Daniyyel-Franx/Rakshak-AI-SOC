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
  hint,
}: {
  label: string
  value: string | number
  icon: LucideIcon
  tone?: "muted" | "low" | "medium" | "high" | "critical" | "primary"
  hint?: string
}) {
  const toneColor: Record<string, string> = {
    muted: "text-muted-foreground",
    primary: "text-[var(--chart-1)]",
    low: "text-[var(--chart-4)]",
    medium: "text-[var(--chart-2)]",
    high: "text-[var(--chart-3)]",
    critical: "text-[var(--destructive)]",
  }
  return (
    <Card className="flex flex-col gap-2 p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </span>
        <Icon className={`h-4 w-4 ${toneColor[tone]}`} />
      </div>
      <span className={`font-mono text-2xl font-semibold ${toneColor[tone]}`}>{value}</span>
      {hint ? <span className="text-xs text-muted-foreground">{hint}</span> : null}
    </Card>
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

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <StatCard label="Total events" value={m.total_events} icon={Activity} tone="primary" />
      <StatCard label="Active incidents" value={m.active_incidents} icon={AlertTriangle} tone="medium" />
      <StatCard
        label="Critical"
        value={m.critical_incidents}
        icon={ShieldAlert}
        tone={m.critical_incidents > 0 ? "critical" : "muted"}
      />
      <StatCard
        label="Avg risk"
        value={m.average_risk.toFixed(0)}
        icon={Gauge}
        tone={riskTone(m.average_risk)}
      />
      <StatCard label="Events / min" value={m.events_per_minute.toFixed(1)} icon={Zap} tone="primary" />
      <StatCard
        label="Queued offline"
        value={m.queued_offline_events}
        icon={Inbox}
        tone={m.queued_offline_events > 0 ? "medium" : "muted"}
      />
    </div>
  )
}
