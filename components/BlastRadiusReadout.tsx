"use client"

/**
 * BlastRadiusReadout — HUD-style score card per the Stitch design spec.
 *
 * Design tokens used (from Stitch "Deep Space HUD Incident Response"):
 *   - Surface glass:  rgba(12,18,34,0.65) + backdrop-blur(16px)
 *   - Border:         rgba(0,240,255,0.18) electric cyan
 *   - Primary number: #00f0ff (electric cyan)
 *   - Label caps:     JetBrains Mono, 0.6875rem, tracking 0.12em
 *   - Bar fill:       violet #a855f7 (blast radius zone color)
 *   - Glow on highest contributor: rgba(168,85,247,0.45)
 *
 * Pure presentational — all data is passed as props.
 */

import type { BlastRadiusHostResult } from "@/lib/types"

interface Props {
  result: BlastRadiusHostResult
}

export function BlastRadiusReadout({ result }: Props) {
  const { host, score, contributing_nodes } = result
  const maxContrib =
    contributing_nodes.length > 0
      ? Math.max(...contributing_nodes.map((n) => n.contribution))
      : 1

  const riskLevel = score > 20 ? "CRITICAL" : score > 10 ? "ELEVATED" : "CONTAINED"
  const riskColor =
    score > 20
      ? "#ff0055"
      : score > 10
        ? "#ffb020"
        : "#00e5a3"

  return (
    <div
      className="flex flex-col gap-3 rounded-md p-4"
      style={{
        background: "rgba(12,18,34,0.75)",
        border: "1px solid rgba(0,240,255,0.18)",
        backdropFilter: "blur(16px)",
        boxShadow:
          "0 0 20px -4px rgba(0,240,255,0.10), inset 0 1px 0 0 rgba(255,255,255,0.06)",
      }}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <p
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "0.6875rem",
              fontWeight: 600,
              letterSpacing: "0.12em",
              color: "rgba(185,202,203,0.7)",
              textTransform: "uppercase",
            }}
          >
            BLAST RADIUS
          </p>
          <p
            className="mt-0.5 truncate max-w-[180px]"
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "0.75rem",
              color: "#00dbe9",
            }}
            title={host}
          >
            {host}
          </p>
        </div>
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "0.65rem",
            fontWeight: 600,
            letterSpacing: "0.1em",
            color: riskColor,
            border: `1px solid ${riskColor}`,
            padding: "1px 6px",
            borderRadius: "2px",
            background: `${riskColor}18`,
            whiteSpace: "nowrap",
          }}
        >
          [ {riskLevel} ]
        </span>
      </div>

      {/* Large score display */}
      <div className="flex items-baseline gap-1.5">
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "2.25rem",
            fontWeight: 700,
            lineHeight: 1,
            color: "#00f0ff",
            textShadow: "0 0 20px rgba(0,240,255,0.55)",
          }}
        >
          {score.toFixed(2)}
        </span>
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "0.7rem",
            color: "rgba(185,202,203,0.5)",
            letterSpacing: "0.05em",
          }}
        >
          pts
        </span>
      </div>

      {/* Contributing node breakdown */}
      {contributing_nodes.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <p
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "0.6875rem",
              fontWeight: 600,
              letterSpacing: "0.12em",
              color: "rgba(185,202,203,0.5)",
              textTransform: "uppercase",
            }}
          >
            CONTRIBUTING NODES
          </p>
          {contributing_nodes.map((n) => {
            const pct = (n.contribution / maxContrib) * 100
            const isTop = n.contribution === maxContrib
            return (
              <div key={n.node} className="flex flex-col gap-0.5">
                <div className="flex items-center justify-between gap-2">
                  <span
                    className="truncate"
                    style={{
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: "0.7rem",
                      color: isTop ? "#a855f7" : "#b9cacb",
                      maxWidth: "130px",
                    }}
                    title={n.node}
                  >
                    {n.node}
                  </span>
                  <div className="flex items-center gap-2 shrink-0">
                    <span
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: "0.6rem",
                        color: "rgba(185,202,203,0.45)",
                      }}
                    >
                      w={n.weight} d={n.distance}
                    </span>
                    <span
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: "0.68rem",
                        color: isTop ? "#a855f7" : "#849495",
                      }}
                    >
                      {n.contribution.toFixed(3)}
                    </span>
                  </div>
                </div>
                {/* Proportional bar */}
                <div
                  className="h-[3px] w-full rounded-full overflow-hidden"
                  style={{ background: "rgba(255,255,255,0.06)" }}
                >
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${pct}%`,
                      background: isTop
                        ? "linear-gradient(90deg,#a855f7,#7c3aed)"
                        : "rgba(0,240,255,0.45)",
                      boxShadow: isTop ? "0 0 6px rgba(168,85,247,0.6)" : "none",
                    }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}

      {contributing_nodes.length === 0 && (
        <p
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "0.72rem",
            color: "rgba(185,202,203,0.4)",
          }}
        >
          No reachable topology nodes from this host.
        </p>
      )}
    </div>
  )
}
