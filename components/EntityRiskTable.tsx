"use client"

import { Card } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useMetrics } from "@/lib/hooks"
import { riskTone, SEVERITY_COLOR } from "@/lib/ui"
import type { MetricsSummary } from "@/lib/types"

export function EntityRiskTable({ metrics }: { metrics?: MetricsSummary }) {
  const swr = useMetrics()
  const m = metrics ?? swr.data
  const rows = (m?.top_entities ?? []).slice(0, 8)

  return (
    <Card className="flex flex-col gap-2 p-4">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Top risky entities
      </h3>
      {rows.length === 0 ? (
        <p className="py-8 text-center text-xs text-muted-foreground">No scored entities yet.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              <TableHead className="h-8 text-[10px] uppercase">Entity</TableHead>
              <TableHead className="h-8 w-16 text-right text-[10px] uppercase">Risk</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => {
              const tone = riskTone(r.risk)
              return (
                <TableRow key={r.entity} className="border-border">
                  <TableCell className="py-1.5 font-mono text-xs">{r.entity}</TableCell>
                  <TableCell className="py-1.5 text-right">
                    <span
                      className="inline-flex min-w-[34px] justify-center rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold"
                      style={{
                        color: SEVERITY_COLOR[tone],
                        backgroundColor: `color-mix(in srgb, ${SEVERITY_COLOR[tone]} 18%, transparent)`,
                      }}
                    >
                      {r.risk.toFixed(0)}
                    </span>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      )}
    </Card>
  )
}
