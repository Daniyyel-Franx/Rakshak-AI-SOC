"use client"

import {
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
import type { MetricsSummary } from "@/lib/types"

function tooltipStyle() {
  return {
    backgroundColor: "var(--popover)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    fontSize: 11,
    color: "var(--popover-foreground)",
  }
}

export function TechniqueChart({ metrics }: { metrics?: MetricsSummary }) {
  const swr = useMetrics()
  const m = metrics ?? swr.data

  const data = m
    ? Object.entries(m.techniques)
        .map(([id, count]) => ({ id, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8)
    : []

  return (
    <Card className="flex flex-col gap-2 p-4">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        ATT&amp;CK technique distribution
      </h3>
      <div className="h-48 w-full">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 4, right: 12, left: 8, bottom: 0 }}
            >
              <XAxis type="number" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} tickLine={false} axisLine={false} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="id"
                tick={{ fontSize: 9, fill: "var(--foreground)", fontFamily: "var(--font-mono)" }}
                tickLine={false}
                axisLine={false}
                width={72}
              />
              <Tooltip contentStyle={tooltipStyle()} cursor={{ fill: "var(--accent)" }} />
              <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                {data.map((d) => (
                  <Cell key={d.id} fill="var(--chart-1)" />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            No techniques mapped yet
          </div>
        )}
      </div>
    </Card>
  )
}
