"use client"

import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { severityFromId, SEVERITY_COLOR, fmtDateTime } from "@/lib/ui"
import type { TimelineEntry } from "@/lib/types"

export function IncidentTimeline({ timeline }: { timeline: TimelineEntry[] }) {
  if (!timeline || timeline.length === 0) {
    return (
      <Card className="p-4 text-sm text-muted-foreground">No timeline events for this incident.</Card>
    )
  }
  return (
    <Card className="flex flex-col gap-2 p-4">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Incident timeline
      </h3>
      <ol className="relative space-y-0 border-l border-border pl-4">
        {timeline.map((t) => {
          const sev = severityFromId(t.severity_id)
          return (
            <li key={t.event_id} className="relative pb-4 last:pb-0">
              <span
                className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full ring-4 ring-card"
                style={{ backgroundColor: SEVERITY_COLOR[sev] }}
                aria-hidden
              />
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] text-muted-foreground">
                  {fmtDateTime(t.time)}
                </span>
                <Badge variant="outline" className="h-4 px-1 text-[9px]">
                  {t.event_class.replace("_activity", "")}
                </Badge>
                <span className="font-mono text-[9px] text-muted-foreground">{t.event_id}</span>
              </div>
              <p className="text-pretty text-xs text-foreground">{t.message}</p>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}
