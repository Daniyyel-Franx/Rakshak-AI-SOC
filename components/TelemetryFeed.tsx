"use client"

import { useEffect, useMemo, useState } from "react"
import { ChevronRight, Filter } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useTelemetry } from "@/lib/hooks"
import { severityFromId, SEVERITY_COLOR, fmtTime } from "@/lib/ui"
import type { OcsfEvent } from "@/lib/types"

const ALL = "__all__"

function str(v: unknown): string {
  return typeof v === "string" ? v : ""
}

export function TelemetryFeed({ siteFilter }: { siteFilter?: string } = {}) {
  const { data, isLoading, error } = useTelemetry(80)
  const [cls, setCls] = useState(ALL)
  const [sev, setSev] = useState(ALL)
  const [site, setSite] = useState(siteFilter ?? ALL)
  const [selected, setSelected] = useState<OcsfEvent | null>(null)

  useEffect(() => {
    if (siteFilter !== undefined) {
      setSite(siteFilter)
    }
  }, [siteFilter])

  const items = data?.items ?? []

  const classes = useMemo(() => [...new Set(items.map((e) => e.event_class))].sort(), [items])
  const sites = useMemo(() => [...new Set(items.map((e) => e.site_id))].sort(), [items])

  const filtered = items.filter((e) => {
    if (cls !== ALL && e.event_class !== cls) return false
    if (sev !== ALL && severityFromId(e.severity_id) !== sev) return false
    if (site !== ALL && e.site_id !== site) return false
    return true
  })

  return (
    <Card className="flex h-full min-h-[420px] flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          Live telemetry
          <span className="text-xs font-normal text-muted-foreground">
            ({filtered.length}/{items.length})
          </span>
        </h3>
        <div className="flex flex-wrap gap-1.5">
          <FilterSelect value={cls} onChange={setCls} placeholder="Class" options={classes} />
          <FilterSelect
            value={sev}
            onChange={setSev}
            placeholder="Severity"
            options={["low", "medium", "high", "critical"]}
          />
          <FilterSelect value={site} onChange={setSite} placeholder="Site" options={sites} />
        </div>
      </div>

      <div className="rakshak-scroll flex-1 space-y-1.5 overflow-y-auto pr-1">
        {isLoading && items.length === 0 ? (
          Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)
        ) : error ? (
          <p className="py-8 text-center text-sm text-[var(--chart-2)]">
            Telemetry unavailable (degraded).
          </p>
        ) : filtered.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">No events match filters.</p>
        ) : (
          filtered.map((e) => {
            const sevLevel = severityFromId(e.severity_id)
            return (
              <button
                key={e.event_id}
                onClick={() => setSelected(e)}
                className="flex w-full items-start gap-2 rounded-md border border-transparent bg-secondary/40 px-2.5 py-2 text-left transition-colors hover:border-border hover:bg-secondary"
              >
                <span
                  className="mt-1 h-2 w-2 shrink-0 rounded-full"
                  style={{ backgroundColor: SEVERITY_COLOR[sevLevel] }}
                  aria-hidden
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground">
                      {fmtTime(e.event_time)}
                    </span>
                    <Badge variant="outline" className="h-4 px-1 text-[9px]">
                      {e.event_class.replace("_activity", "")}
                    </Badge>
                    <span className="font-mono text-[10px] text-muted-foreground">{e.site_id}</span>
                  </div>
                  <p className="truncate text-xs text-foreground">
                    {e.message || `${str(e.user?.["name"]) || "—"} @ ${str(e.device?.["hostname"]) || "—"}`}
                  </p>
                </div>
                <ChevronRight className="mt-1 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              </button>
            )
          })
        )}
      </div>

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-h-[80vh] max-w-2xl overflow-hidden">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm">
              {selected?.event_id} · {selected?.event_class}
            </DialogTitle>
          </DialogHeader>
          {selected ? (
            <div className="space-y-3 overflow-y-auto rakshak-scroll">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <Field label="Event time" value={selected.event_time} />
                <Field label="Received" value={selected.received_time} />
                <Field label="Site" value={selected.site_id} />
                <Field label="Type UID" value={String(selected.type_uid)} />
                <Field label="Severity id" value={String(selected.severity_id)} />
                <Field label="Status id" value={String(selected.status_id)} />
              </div>
              <div>
                <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                  Raw OCSF-compatible JSON
                </p>
                <pre className="rakshak-scroll max-h-72 overflow-auto rounded-md border bg-background p-3 font-mono text-[10px] leading-relaxed text-foreground">
                  {JSON.stringify(selected, null, 2)}
                </pre>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-background px-2 py-1.5">
      <p className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="truncate font-mono text-xs text-foreground">{value || "—"}</p>
    </div>
  )
}

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
}: {
  value: string
  onChange: (v: string) => void
  placeholder: string
  options: string[]
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v ?? ALL)}>
      <SelectTrigger className="h-7 w-auto min-w-[92px] text-xs">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>All {placeholder.toLowerCase()}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o} value={o} className="text-xs">
            {o}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
