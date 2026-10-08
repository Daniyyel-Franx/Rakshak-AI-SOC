"use client"

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { Card } from "@/components/ui/card"
import { useMetrics } from "@/lib/hooks"
import { fmtTime, severityColor } from "@/lib/ui"
import type { MetricsSummary } from "@/lib/types"

const SEV_ORDER: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}
const RISK_COLOR = ["var(--chart-4)", "var(--chart-4)", "var(--chart-2)", "var(--chart-2)", "var(--chart-3)", "var(--chart-3)", "var(--chart-3)", "var(--destructive)", "var(--destructive)", "var(--destructive)"]

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card className="flex flex-col gap-2 p-4">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{title}</h3>
      <div className="h-40 w-full">{children}</div>
    </Card>
  )
}

function EmptyChart({ label }: { label: string }) {
  return (
    <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
      {label}
    </div>
  )
}

function tooltipStyle() {
  return {
    backgroundColor: "var(--popover)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    fontSize: 11,
    color: "var(--popover-foreground)",
  }
}

export function SeverityChart({ metrics }: { metrics?: MetricsSummary }) {
  const swr = useMetrics()
  const m = metrics ?? swr.data
  if (!m) return <ChartCard title="Severity distribution"><EmptyChart label="Loading…" /></ChartCard>

  const sevData = Object.entries(m.severity_counts)
    .map(([sev, count]) => ({
      id: sev,
      name: sev,
      count: Number(count),
      order: SEV_ORDER[sev.toLowerCase()] ?? 99,
      color: severityColor(sev),
    }))
    .sort((a, b) => a.order - b.order)
  const rateData = m.event_rate_timeseries.map((p: { minute: string; count: number }) => ({
    ...p,
    t: fmtTime(p.minute + ":00"),
  }))

  const hasSev = sevData.some((d: { count: number }) => d.count > 0)
  const hasRate = rateData.some((d: { count: number }) => d.count > 0)

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
      <ChartCard title="Event rate over time">
        {hasRate ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={rateData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="rate" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--chart-1)" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="var(--chart-1)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
              <Tooltip contentStyle={tooltipStyle()} />
              <Area type="monotone" dataKey="count" stroke="var(--chart-1)" fill="url(#rate)" strokeWidth={1.6} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <EmptyChart label="No event-rate data" />
        )}
      </ChartCard>

      <ChartCard title="Severity distribution">
        {hasSev ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={sevData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
              <Tooltip contentStyle={tooltipStyle()} cursor={{ fill: "var(--accent)" }} />
              <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                {sevData.map((d) => (
                  <Cell key={d.name} fill={d.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <EmptyChart label="No severity data" />
        )}
      </ChartCard>
    </div>
  )
}

export function RiskHistogram({ metrics }: { metrics?: MetricsSummary }) {
  const swr = useMetrics()
  const m = metrics ?? swr.data
  if (!m) return <ChartCard title="Risk distribution"><EmptyChart label="Loading…" /></ChartCard>
  const data = m.risk_distribution
  const has = data.some((d: { count: number }) => d.count > 0)
  return (
    <ChartCard title="Risk score histogram">
      {has ? (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
            <XAxis dataKey="bucket" tick={{ fontSize: 8, fill: "var(--muted-foreground)" }} tickLine={false} axisLine={false} interval={0} />
            <YAxis tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
            <Tooltip contentStyle={tooltipStyle()} cursor={{ fill: "var(--accent)" }} />
            <Bar dataKey="count" radius={[3, 3, 0, 0]}>
              {data.map((d: { bucket: string; count: number }, i: number) => (
                <Cell key={d.bucket} fill={RISK_COLOR[i] ?? "var(--chart-5)"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <EmptyChart label="No risk-distribution data" />
      )}
    </ChartCard>
  )
}
