"use client"

import { Activity, WifiOff, Database, BrainCircuit, ShieldAlert } from "lucide-react"
import { useHealth, useConnectionMode, useLinkStatus } from "@/lib/hooks"

function Dot({ ok, warn }: { ok: boolean; warn?: boolean }) {
  const color = ok ? "bg-[var(--chart-4)]" : warn ? "bg-[var(--chart-2)]" : "bg-[var(--chart-3)]"
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} aria-hidden />
}

export function ConnectionStatus() {
  const { data: health } = useHealth()
  const { data: link } = useLinkStatus()
  const mode = useConnectionMode()

  const backendOnline = mode === "live"
  const ollamaOk = health?.ollama_available ?? false
  const linkOnline = link?.online ?? true
  const queued = link?.queued ?? 0

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
      <div className="flex items-center gap-1.5" title="Backend API connection">
        {backendOnline ? (
          <Activity className="h-3.5 w-3.5 text-[var(--chart-4)]" />
        ) : (
          <WifiOff className="h-3.5 w-3.5 text-[var(--chart-2)]" />
        )}
        <span className="text-muted-foreground">API</span>
        <span className={backendOnline ? "text-foreground" : "text-[var(--chart-2)]"}>
          {backendOnline ? "live" : "seeded"}
        </span>
      </div>

      <div className="flex items-center gap-1.5" title="Local database">
        <Database className="h-3.5 w-3.5 text-muted-foreground" />
        <Dot ok={(health?.database ?? "ok") === "ok"} />
        <span className="text-muted-foreground">DB</span>
      </div>

      <div className="flex items-center gap-1.5" title="Local Ollama analyst model">
        <BrainCircuit className="h-3.5 w-3.5 text-muted-foreground" />
        <Dot ok={ollamaOk} warn />
        <span className="text-muted-foreground">Ollama</span>
        <span className="text-foreground">{ollamaOk ? "ready" : "fallback"}</span>
      </div>

      <div className="flex items-center gap-1.5" title="Central streaming link">
        <ShieldAlert className="h-3.5 w-3.5 text-muted-foreground" />
        <Dot ok={linkOnline} warn={!linkOnline} />
        <span className="text-muted-foreground">Link</span>
        <span className={linkOnline ? "text-foreground" : "text-[var(--chart-2)]"}>
          {linkOnline ? "connected" : `offline · ${queued} queued`}
        </span>
      </div>
    </div>
  )
}
