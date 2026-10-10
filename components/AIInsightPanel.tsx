"use client"

import { useState, useEffect } from "react"
import { BrainCircuit, Copy, Check, Sparkles, ShieldQuestion, AlertCircle } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { analyzeIncident } from "@/lib/api"
import { aiAnalysisSchema } from "@/lib/validation"
import { riskTone, SEVERITY_COLOR } from "@/lib/ui"
import type { AiAnalysis } from "@/lib/types"

export function AIInsightPanel({
  incidentId,
  initial,
}: {
  incidentId: string | null
  initial?: AiAnalysis | null
}) {
  const [analysis, setAnalysis] = useState<AiAnalysis | null>(
    initial && (initial as unknown as Record<string, unknown>).assessment ? initial : null
  )
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (initial && (initial as unknown as Record<string, unknown>).assessment) {
      setAnalysis(initial)
    } else {
      setAnalysis(null)
    }
  }, [initial, incidentId])

  async function run() {
    if (!incidentId) return
    setLoading(true)
    setError(null)
    try {
      const res = await analyzeIncident(incidentId)
      // Defensive: validate structured output before rendering.
      setAnalysis(aiAnalysisSchema.parse(res))
    } catch {
      setError("Deterministic analysis failed validation or the request errored. No result shown.")
    } finally {
      setLoading(false)
    }
  }

  async function copy() {
    if (!analysis) return
    await navigator.clipboard.writeText(JSON.stringify(analysis, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const tone = analysis ? riskTone(analysis.threat_score) : "low"
  const isFallback = analysis?.analysis_source === "rule_engine_fallback"

  return (
    <Card className="flex flex-col gap-3 p-4">
      <div className="flex items-center justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <BrainCircuit className="h-4 w-4 text-[#00f0ff]" />
          Deterministic investigation analysis
        </h3>
        <div className="flex items-center gap-1.5">
          {analysis ? (
            <Badge
              variant="outline"
              className="gap-1 text-[9px]"
              style={{
                borderColor: isFallback ? "#00e5a3" : "#ffb020",
                color: isFallback ? "#00e5a3" : "#ffb020",
              }}
            >
              {isFallback ? "DETERMINISTIC ANALYSIS (PART 1)" : "LOCAL LLM: PART 2 (DISABLED)"}
            </Badge>
          ) : null}
          <Button size="sm" className="h-7 gap-1 text-xs" disabled={!incidentId || loading} onClick={run}>
            <Sparkles className="h-3.5 w-3.5" />
            {loading ? "Analysing…" : analysis ? "Re-run" : "Generate deterministic insight"}
          </Button>
        </div>
      </div>

      {!incidentId ? (
        <p className="py-6 text-center text-xs text-muted-foreground">
          Select an incident to enable evidence-grounded analysis.
        </p>
      ) : error ? (
        <div className="flex items-start gap-2 rounded-md border border-[var(--chart-3)]/40 bg-[var(--chart-3)]/10 p-3 text-xs text-[var(--chart-3)]">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : !analysis ? (
        <p className="py-6 text-center text-xs text-muted-foreground">
          No analysis yet. Detection is done by the deterministic engine; this panel only
          summarises grounded evidence.
        </p>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <ScoreBadge label="Threat" value={analysis.threat_score} tone={tone} />
            <ScoreBadge label="Confidence" value={Math.round(analysis.confidence * 100)} suffix="%" tone="medium" />
            <Button variant="ghost" size="sm" className="ml-auto h-7 gap-1 text-xs" onClick={copy}>
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              Copy JSON
            </Button>
          </div>

          <Section title="Assessment">
            <p className="text-pretty text-xs leading-relaxed text-foreground">{analysis.assessment}</p>
          </Section>

          <Section title="Attack path summary">
            <p className="text-pretty text-xs leading-relaxed text-muted-foreground">
              {analysis.attack_path_summary}
            </p>
          </Section>

          <Section title={`ATT&CK techniques (${analysis.attack_techniques.length})`}>
            <div className="space-y-1.5">
              {analysis.attack_techniques.map((t) => (
                <div key={t.id} className="rounded-md border bg-background px-2.5 py-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-[var(--chart-1)]">{t.id}</span>
                    <span className="text-xs text-foreground">{t.name}</span>
                    <Badge variant="outline" className="h-4 px-1 text-[9px]">
                      {t.tactic}
                    </Badge>
                    <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                      {Math.round(t.confidence * 100)}%
                    </span>
                  </div>
                  <p className="mt-0.5 font-mono text-[9px] text-muted-foreground">
                    evidence: {t.evidence_refs.join(", ") || "none"}
                  </p>
                </div>
              ))}
            </div>
          </Section>

          <Section title={`Evidence references (${analysis.evidence_refs.length})`}>
            <div className="flex flex-wrap gap-1">
              {analysis.evidence_refs.map((e) => (
                <Badge key={e} variant="secondary" className="font-mono text-[9px]">
                  {e}
                </Badge>
              ))}
            </div>
          </Section>

          {analysis.missing_evidence.length > 0 ? (
            <Section title="Missing evidence / uncertainty">
              <ul className="space-y-0.5">
                {analysis.missing_evidence.map((mv, i) => (
                  <li key={i} className="flex items-start gap-1.5 text-xs text-[var(--chart-2)]">
                    <ShieldQuestion className="mt-0.5 h-3 w-3 shrink-0" />
                    {mv}
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}

          <Section title="Recommended next steps (safe)">
            <div className="space-y-1">
              {analysis.recommended_next_steps.map((s, i) => (
                <div key={i} className="flex items-center gap-2 rounded-md border bg-background px-2.5 py-1.5">
                  <span className="font-mono text-xs text-foreground">{s.action}</span>
                  <Badge variant="outline" className="h-4 px-1 text-[9px]">
                    {s.risk_class}
                  </Badge>
                  {s.requires_approval ? (
                    <span className="ml-auto text-[9px] text-[var(--chart-2)]">approval required</span>
                  ) : (
                    <span className="ml-auto text-[9px] text-muted-foreground">auto-eligible</span>
                  )}
                </div>
              ))}
            </div>
          </Section>

          <p className="rounded-md border border-dashed border-border px-2.5 py-1.5 text-[10px] text-muted-foreground">
            {analysis.safety_notice}
          </p>
        </div>
      )}
    </Card>
  )
}

function ScoreBadge({
  label,
  value,
  suffix,
  tone,
}: {
  label: string
  value: number
  suffix?: string
  tone: "low" | "medium" | "high" | "critical"
}) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className="font-mono text-lg font-semibold" style={{ color: SEVERITY_COLOR[tone] }}>
        {value}
        {suffix ?? ""}
      </span>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{title}</p>
      {children}
    </div>
  )
}
