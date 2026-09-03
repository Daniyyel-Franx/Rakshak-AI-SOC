"use client"

import { useState } from "react"
import { ShieldCheck, Lock, KeyRound, Bug, FileSearch, FolderPlus, AlertTriangle } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog"
import { simulateAction } from "@/lib/api"
import { RISK_CLASS_LABEL } from "@/lib/ui"
import type { SimulatedActionResponse } from "@/lib/types"

const ACTIONS: { type: string; label: string; icon: typeof Lock; risk: string }[] = [
  { type: "simulate_isolate_endpoint", label: "Isolate endpoint", icon: Lock, risk: "R2" },
  { type: "simulate_revoke_session", label: "Revoke session", icon: KeyRound, risk: "R2" },
  { type: "activate_decoy", label: "Activate decoy", icon: Bug, risk: "R1" },
  { type: "collect_mock_evidence", label: "Collect evidence", icon: FileSearch, risk: "R0" },
  { type: "create_case", label: "Create case", icon: FolderPlus, risk: "R0" },
]

export function ResponseActions({ incidentId, target }: { incidentId: string | null; target: string }) {
  const [pending, setPending] = useState<(typeof ACTIONS)[number] | null>(null)
  const [result, setResult] = useState<SimulatedActionResponse | null>(null)
  const [busy, setBusy] = useState(false)

  async function confirm() {
    if (!pending || !incidentId) return
    setBusy(true)
    try {
      const res = await simulateAction({
        incident_id: incidentId,
        action_type: pending.type,
        target: target || "synthetic-target",
        approved_by: "soc-analyst",
      })
      setResult(res)
    } finally {
      setBusy(false)
      setPending(null)
    }
  }

  return (
    <Card className="flex flex-col gap-3 p-4">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <ShieldCheck className="h-4 w-4 text-[var(--chart-4)]" />
          Response actions
        </h3>
        <Badge
          className="gap-1 border-[var(--chart-2)] bg-[var(--chart-2)]/10 text-[9px] text-[var(--chart-2)]"
          variant="outline"
        >
          <AlertTriangle className="h-3 w-3" />
          SIMULATION ONLY
        </Badge>
      </div>

      <p className="text-xs text-muted-foreground">
        Every action is synthetic and policy-controlled. No real shell, firewall or account change is
        ever executed.
      </p>

      <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
        {ACTIONS.map((a) => {
          const Icon = a.icon
          return (
            <Button
              key={a.type}
              variant="secondary"
              className="h-auto justify-start gap-2 py-2 text-xs"
              disabled={!incidentId}
              onClick={() => setPending(a)}
            >
              <Icon className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="flex-1 text-left">{a.label}</span>
              <Badge variant="outline" className="h-4 px-1 text-[9px]">
                {a.risk}
              </Badge>
            </Button>
          )
        })}
      </div>

      {result ? (
        <div className="space-y-1.5 rounded-md border bg-background p-3">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-foreground">{result.action_type}</span>
            <Badge
              variant="outline"
              className="text-[9px]"
              style={{
                borderColor: result.approval_state === "approved" ? "var(--chart-4)" : "var(--chart-2)",
                color: result.approval_state === "approved" ? "var(--chart-4)" : "var(--chart-2)",
              }}
            >
              {result.approval_state}
            </Badge>
            <Badge variant="secondary" className="text-[9px]">
              {RISK_CLASS_LABEL[result.policy_risk_class] ?? result.policy_risk_class}
            </Badge>
          </div>
          <p className="text-xs text-foreground">{result.result}</p>
          <p className="font-mono text-[10px] text-muted-foreground">
            target: {result.target} · action_id: {result.action_id}
          </p>
          <p className="font-mono text-[10px] text-muted-foreground">
            rollback: {JSON.stringify(result.rollback)}
          </p>
        </div>
      ) : null}

      <Dialog open={!!pending} onOpenChange={(o) => !o && setPending(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-[var(--chart-2)]" />
              Confirm simulated action
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-2 text-sm">
            <p className="text-foreground">
              Simulate <span className="font-mono text-[var(--chart-1)]">{pending?.label}</span> against{" "}
              <span className="font-mono">{target || "synthetic-target"}</span>?
            </p>
            <p className="rounded-md border border-dashed px-2.5 py-1.5 text-xs text-muted-foreground">
              Policy class {pending?.risk} · {RISK_CLASS_LABEL[pending?.risk ?? "R0"]}. This runs only
              against the synthetic cyber-range. No production system is affected.
            </p>
          </div>
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button size="sm" disabled={busy} onClick={confirm}>
              {busy ? "Executing…" : "Confirm simulation"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
