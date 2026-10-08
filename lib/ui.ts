import type { SeverityLevel } from "./types"

// Severity -> chart/token color. Uses the 5-color design tokens.
export const SEVERITY_COLOR: Record<string, string> = {
  info: "var(--chart-1)", // cyan
  low: "var(--chart-4)", // emerald
  medium: "var(--chart-2)", // amber
  high: "var(--chart-3)", // red
  critical: "var(--destructive)",
}

export function severityColor(s: string): string {
  const norm = (s || "").toLowerCase()
  return SEVERITY_COLOR[norm] ?? "var(--chart-1)"
}

export const SEVERITY_ID_LABEL: Record<number, SeverityLevel> = {
  1: "low",
  2: "low",
  3: "medium",
  4: "high",
  5: "critical",
  6: "critical",
}

export function severityFromId(id: number): SeverityLevel {
  return SEVERITY_ID_LABEL[id] ?? "low"
}

// Entity type -> accent color for the attack graph nodes.
export const ENTITY_COLOR: Record<string, string> = {
  attacker_ip: "var(--chart-3)",
  user: "var(--chart-2)",
  source_host: "var(--chart-1)",
  target_host: "var(--chart-1)",
  process: "var(--chart-2)",
  service: "var(--chart-5)",
  file: "var(--chart-2)",
  payload: "var(--destructive)",
  decoy: "var(--chart-4)",
  site: "var(--chart-5)",
  incident: "var(--chart-3)",
}

export function entityColor(t: string): string {
  return ENTITY_COLOR[t] ?? "var(--chart-5)"
}

export function fmtTime(iso: string): string {
  if (!iso) return "—"
  try {
    return new Date(iso).toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
  } catch {
    return iso
  }
}

export function fmtDateTime(iso: string): string {
  if (!iso) return "—"
  try {
    return new Date(iso).toLocaleString("en-GB", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    })
  } catch {
    return iso
  }
}

export function riskTone(score: number): SeverityLevel {
  if (score >= 80) return "critical"
  if (score >= 60) return "high"
  if (score >= 30) return "medium"
  return "low"
}

export const RISK_CLASS_LABEL: Record<string, string> = {
  R0: "R0 · Read-only",
  R1: "R1 · Low impact",
  R2: "R2 · Contained impact",
  R3: "R3 · High impact",
}
