"use client"

import { useState } from "react"
import { useSWRConfig } from "swr"
import { Play, Trash2, Unplug, Plug, Loader2 } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useScenarios, useLinkStatus } from "@/lib/hooks"
import { replayScenario, setLink, clearDemo } from "@/lib/api"

export function ScenarioControls({ onReplay }: { onReplay?: (incidentId: string | null) => void }) {
  const { data: scenarios } = useScenarios()
  const { data: link } = useLinkStatus()
  const { mutate } = useSWRConfig()
  const [selected, setSelected] = useState<string>("SCENARIO_1_SSH_COMPROMISE")
  const [busy, setBusy] = useState<string | null>(null)
  const [lastMsg, setLastMsg] = useState<string | null>(null)

  const linkOnline = link?.online ?? true

  function refreshAll() {
    mutate("metrics")
    mutate("incidents")
    mutate(["telemetry", 80])
    mutate(["telemetry", 60])
    mutate("link-status")
  }

  async function doReplay() {
    setBusy("replay")
    try {
      const res = await replayScenario(selected)
      setLastMsg(
        `Replay ${res.status}: ${res.events_ingested} ingested, ${res.duplicates_skipped} duplicates skipped.`,
      )
      refreshAll()
      onReplay?.(res.incident_id)
    } finally {
      setBusy(null)
    }
  }

  async function toggleLink() {
    setBusy("link")
    try {
      const res = await setLink(!linkOnline)
      setLastMsg(
        !linkOnline
          ? "Central link restored. Queued events replayed without duplication."
          : `Link loss simulated. Local scoring continues; events queue locally (${res.queued}).`,
      )
      refreshAll()
    } finally {
      setBusy(null)
    }
  }

  async function doClear() {
    setBusy("clear")
    try {
      await clearDemo()
      setLastMsg("Demo data cleared.")
      refreshAll()
      onReplay?.(null)
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card className="flex flex-col gap-3 p-4">
      <h3 className="text-sm font-semibold">Scenario controls</h3>

      <div className="flex flex-col gap-2">
        <Select value={selected} onValueChange={(v) => v && setSelected(v)}>
          <SelectTrigger className="text-xs">
            <SelectValue placeholder="Select scenario" />
          </SelectTrigger>
          <SelectContent>
            {(scenarios ?? []).map((s) => (
              <SelectItem key={s.scenario_id} value={s.scenario_id} className="text-xs">
                <span className="flex items-center gap-2">
                  {s.name}
                  <Badge
                    variant="outline"
                    className="h-4 px-1 text-[9px]"
                    style={{ color: s.benign ? "var(--chart-4)" : "var(--chart-3)" }}
                  >
                    {s.benign ? "benign" : s.severity}
                  </Badge>
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="grid grid-cols-2 gap-1.5">
          <Button size="sm" className="gap-1 text-xs" disabled={busy !== null} onClick={doReplay}>
            {busy === "replay" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            Replay
          </Button>
          <Button
            size="sm"
            variant="secondary"
            className="gap-1 text-xs"
            disabled={busy !== null}
            onClick={toggleLink}
          >
            {busy === "link" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : linkOnline ? (
              <Unplug className="h-3.5 w-3.5" />
            ) : (
              <Plug className="h-3.5 w-3.5" />
            )}
            {linkOnline ? "Simulate link loss" : "Restore link"}
          </Button>
        </div>

        <Button
          size="sm"
          variant="ghost"
          className="gap-1 text-xs text-muted-foreground"
          disabled={busy !== null}
          onClick={doClear}
        >
          {busy === "clear" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
          Clear demo data
        </Button>
      </div>

      {lastMsg ? (
        <p className="rounded-md border border-dashed px-2.5 py-1.5 text-[11px] leading-relaxed text-muted-foreground">
          {lastMsg}
        </p>
      ) : null}
    </Card>
  )
}
