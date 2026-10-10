"use client"

/**
 * BlastRadiusNetworkView — force-directed topology graph for blast radius.
 *
 * Completely separate from AttackPathGraph.tsx (Dagre causal chain).
 * This is an organic force-directed layout showing network trust relationships.
 *
 * Architecture:
 *   1. runForceLayout() (lib/forceLayout.ts) computes positions via d3-force.
 *   2. React Flow renders nodes/edges with its native zoom/pan/interaction.
 *   3. d3-polygon's polygonHull renders the blast radius zone as an SVG path
 *      BEHIND the React Flow nodes, via a custom SVG panel.
 *   4. Custom node type: glass + bloom glow scaled by contribution value.
 *      3 glow tiers: low (cyan), medium (amber), high (violet/red bloom).
 *   5. Custom smoothstep bezier edges (React Flow built-in type "smoothstep").
 *
 * Ego-graph dimming scope decision (stated explicitly per task spec):
 *   The blast-radius API only returns nodes IN contributing_nodes — it does NOT
 *   return the full topology (all ~11 nodes). Therefore we cannot dim "nodes
 *   NOT in contributing_nodes" because we don't have that data here.
 *   Scoped to v1: the COMPROMISED HOST renders at full brightness with the
 *   strongest glow + a ⚠ badge. All contributing_nodes render at full opacity.
 *   Full ego-graph dimming (showing full topology at 30% opacity) requires a
 *   separate /api/topology endpoint — documented as a follow-up gap.
 *
 * Design tokens from Stitch "Deep Space HUD Incident Response":
 *   - Blast zone fill:     rgba(168,85,247,0.18) violet, dashed border
 *   - Compromised node:    rgba(255,0,85,0.35) red bloom, full brightness
 *   - High contrib glow:   rgba(168,85,247,0.45) violet bloom
 *   - Med contrib glow:    rgba(255,176,32,0.35) amber
 *   - Low contrib:         rgba(0,240,255,0.20) cyan
 *   - Glass card bg:       rgba(12,18,34,0.70) + backdrop-blur(16px)
 *   - Border:              rgba(0,240,255,0.20)
 */

import { useMemo, useCallback } from "react"
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
  ReactFlowProvider,
  useReactFlow,
  useStore,
} from "reactflow"
import { polygonHull } from "d3-polygon"
import { runForceLayout } from "@/lib/forceLayout"
import type { BlastRadiusHostResult } from "@/lib/types"

// ─── Design constants (exact from Stitch tokens) ────────────────────────────
const COMPROMISED_COLOR = "#ff0055"
const COMPROMISED_GLOW = "0 0 28px 4px rgba(255,0,85,0.45), 0 0 10px 1px rgba(255,0,85,0.35)"
const HIGH_GLOW = "0 0 20px 2px rgba(168,85,247,0.50)"
const MED_GLOW = "0 0 16px 2px rgba(255,176,32,0.40)"
const LOW_GLOW = "0 0 10px 1px rgba(0,240,255,0.25)"
const ZONE_FILL = "rgba(168,85,247,0.12)"
const ZONE_STROKE = "rgba(168,85,247,0.55)"

// ─── Node data shape ─────────────────────────────────────────────────────────
interface BlastNodeData {
  label: string
  isCompromised: boolean
  weight: number
  distance: number
  contribution: number
  maxContrib: number
}

// ─── Custom node renderer ────────────────────────────────────────────────────
function BlastNode({ data }: NodeProps<BlastNodeData>) {
  const { label, isCompromised, contribution, maxContrib, weight, distance } = data

  const ratio = maxContrib > 0 ? contribution / maxContrib : 0
  let glowStyle: string
  let borderColor: string
  if (isCompromised) {
    glowStyle = COMPROMISED_GLOW
    borderColor = COMPROMISED_COLOR
  } else if (ratio >= 0.7) {
    glowStyle = HIGH_GLOW
    borderColor = "#a855f7"
  } else if (ratio >= 0.35) {
    glowStyle = MED_GLOW
    borderColor = "#ffb020"
  } else {
    glowStyle = LOW_GLOW
    borderColor = "rgba(0,240,255,0.45)"
  }

  return (
    <div
      style={{
        minWidth: 110,
        maxWidth: 160,
        background: "rgba(12,18,34,0.78)",
        border: `1px solid ${borderColor}`,
        borderRadius: 6,
        padding: "8px 10px",
        textAlign: "center",
        backdropFilter: "blur(14px)",
        boxShadow: glowStyle,
        cursor: "default",
        position: "relative",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0, pointerEvents: "none" }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0, pointerEvents: "none" }} />

      {isCompromised && (
        <div
          style={{
            position: "absolute",
            top: -8,
            right: -8,
            width: 16,
            height: 16,
            borderRadius: "50%",
            background: COMPROMISED_COLOR,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 9,
            boxShadow: "0 0 8px rgba(255,0,85,0.7)",
          }}
          title="Compromised host"
        >
          ⚠
        </div>
      )}

      <p
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "0.6rem",
          fontWeight: 600,
          letterSpacing: "0.12em",
          color: isCompromised ? COMPROMISED_COLOR : "rgba(185,202,203,0.6)",
          textTransform: "uppercase",
          marginBottom: 2,
        }}
      >
        {isCompromised ? "COMPROMISED" : `w=${weight} d=${distance}`}
      </p>
      <p
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "0.7rem",
          color: isCompromised ? "#ff6680" : "#e1e2ec",
          wordBreak: "break-all",
        }}
      >
        {label}
      </p>
      {!isCompromised && (
        <p
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "0.6rem",
            color: borderColor,
            marginTop: 2,
          }}
        >
          +{contribution.toFixed(3)}
        </p>
      )}
    </div>
  )
}

const nodeTypes = { blastNode: BlastNode }
const FIT_VIEW_OPTIONS = { padding: 0.25 }
const PRO_OPTIONS = { hideAttribution: true }

// ─── Hull zone SVG overlay (rendered BEHIND React Flow nodes) ─────────────────
/**
 * HullZone uses React Flow's useStore to read current transform and node
 * positions, then renders the convex hull polygon in screen space.
 *
 * We render it as a <panel> in the React Flow SVG layer via panOnScroll=false
 * workaround: actually we inject it as an absolutely-positioned SVG that sits
 * behind the React Flow canvas and uses the viewport transform to track positions.
 */
function HullZone({
  nodePositions,
}: {
  nodePositions: { id: string; x: number; y: number }[]
}) {
  const transform = useStore((s) => s.transform)
  const [tx, ty, tz] = transform

  // Convert flow-space positions to screen-space using the viewport transform
  const screenPoints = nodePositions.map(({ x, y }) => [
    x * tz + tx,
    y * tz + ty,
  ] as [number, number])

  if (screenPoints.length < 3) return null

  const hull = polygonHull(screenPoints)
  if (!hull) return null

  // Expand hull by padding
  const cx = hull.reduce((s, p) => s + p[0], 0) / hull.length
  const cy = hull.reduce((s, p) => s + p[1], 0) / hull.length
  const PAD = 36 * tz
  const expanded = hull.map(([x, y]) => {
    const dx = x - cx
    const dy = y - cy
    const len = Math.sqrt(dx * dx + dy * dy) || 1
    return [x + (dx / len) * PAD, y + (dy / len) * PAD]
  })

  const d = `M ${expanded.map((p) => p.join(",")).join(" L ")} Z`

  return (
    <svg
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        zIndex: 0, // behind React Flow nodes (z-index 3), same level as edges (z-index 0/1)
        overflow: "visible",
      }}
    >
      <defs>
        <filter id="hull-glow">
          <feGaussianBlur stdDeviation="6" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <path
        d={d}
        fill={ZONE_FILL}
        stroke={ZONE_STROKE}
        strokeWidth={1.5}
        strokeDasharray="6 4"
        filter="url(#hull-glow)"
        style={{ animation: "dash-scroll 12s linear infinite" }}
      />
    </svg>
  )
}

// ─── Inner graph component (inside ReactFlowProvider) ────────────────────────
function BlastGraphInner({
  result,
  canvasW,
  canvasH,
}: {
  result: BlastRadiusHostResult
  canvasW: number
  canvasH: number
}) {
  const { host, canonical_host, contributing_nodes, topology_edges } = result
  const rf = useReactFlow()

  const maxContrib = useMemo(
    () =>
      contributing_nodes.length > 0
        ? Math.max(...contributing_nodes.map((n) => n.contribution))
        : 1,
    [contributing_nodes],
  )

  const rootId = canonical_host || host

  // Build layout node list: compromised host + all contributing nodes
  const layoutNodes = useMemo(
    () => [
      { id: rootId },
      ...contributing_nodes.map((n) => ({ id: n.node })),
    ],
    [rootId, contributing_nodes],
  )

  // Actual environmental topology edges from backend (never fabricated)
  const layoutEdges = useMemo(() => {
    if (topology_edges && topology_edges.length > 0) {
      return topology_edges.map((e) => ({
        source: e.source,
        target: e.target,
      }))
    }
    return []
  }, [topology_edges])

  // Run force layout synchronously (stable positions, memoized)
  const positions = useMemo(
    () => runForceLayout(layoutNodes, layoutEdges, canvasW, canvasH),
    [canvasW, canvasH, layoutNodes, layoutEdges],
  )

  const posMap = useMemo(
    () => new Map(positions.map((p) => [p.id, { x: p.x, y: p.y }])),
    [positions],
  )

  // Build React Flow nodes
  const rfNodes: Node<BlastNodeData>[] = useMemo(() => {
    const hostPos = posMap.get(rootId) ?? { x: canvasW / 2, y: canvasH / 2 }
    const nodes: Node<BlastNodeData>[] = [
      {
        id: rootId,
        type: "blastNode",
        position: hostPos,
        draggable: false,
        data: {
          label: host,
          isCompromised: true,
          weight: 0,
          distance: 0,
          contribution: 0,
          maxContrib,
        },
      },
    ]
    for (const cn of contributing_nodes) {
      const pos = posMap.get(cn.node) ?? { x: canvasW / 2, y: canvasH / 2 }
      nodes.push({
        id: cn.node,
        type: "blastNode",
        position: pos,
        draggable: false,
        data: {
          label: cn.node,
          isCompromised: false,
          weight: cn.weight,
          distance: cn.distance,
          contribution: cn.contribution,
          maxContrib,
        },
      })
    }
    return nodes
  }, [rootId, host, contributing_nodes, posMap, canvasW, canvasH, maxContrib])

  // Build React Flow edges from actual environmental topology relationships
  const rfEdges: Edge[] = useMemo(() => {
    if (!topology_edges || topology_edges.length === 0) {
      return []
    }
    return topology_edges.map((e, idx) => {
      // Dynamic coloring based on contributing node impact
      const cnSource = contributing_nodes.find((n) => n.node === e.source)
      const cnTarget = contributing_nodes.find((n) => n.node === e.target)
      const maxEdgeContrib = Math.max(cnSource?.contribution ?? 0, cnTarget?.contribution ?? 0)
      const ratio = maxEdgeContrib / maxContrib

      const edgeColor =
        ratio >= 0.7
          ? "#a855f7"
          : ratio >= 0.35
            ? "#ffb020"
            : "rgba(0,240,255,0.4)"

      const label = e.trust_type ? e.trust_type.replace("_", " ") : undefined

      return {
        id: `br-edge-${e.source}-${e.target}-${idx}`,
        source: e.source,
        target: e.target,
        type: "smoothstep",
        animated: ratio >= 0.7,
        label,
        labelStyle: { fill: "#849495", fontSize: 9, fontFamily: "var(--font-mono)" },
        labelBgStyle: { fill: "rgba(12, 18, 34, 0.85)", rx: 3, ry: 3 },
        style: {
          stroke: edgeColor,
          strokeWidth: 1.2 + ratio * 1.2,
          opacity: 0.7,
        },
      }
    })
  }, [topology_edges, contributing_nodes, maxContrib])

  const fitView = useCallback(() => {
    rf.fitView({ padding: 0.2, duration: 400 })
  }, [rf])

  // Hull zone should enclose ONLY the compromised host and the GENUINELY affected nodes (high/medium impact)
  const hullPositions = useMemo(() => {
    const impactThreshold = 0.35 // matches MED_GLOW / HIGH_GLOW ratio cutoff
    const impactedNodes = contributing_nodes.filter((n) => {
      const ratio = maxContrib > 0 ? n.contribution / maxContrib : 0
      return ratio >= impactThreshold
    })

    const positions = impactedNodes
      .map((n) => posMap.get(n.node))
      .filter((p): p is { x: number; y: number } => !!p)
      .map((p, i) => ({ id: `hull-cn-${i}`, x: p.x, y: p.y }))

    // MUST include the compromised root host so the polygon anchors to the origin of the blast
    const rootPos = posMap.get(rootId)
    if (rootPos) {
      positions.push({ id: "hull-root", x: rootPos.x, y: rootPos.y })
    }

    return positions
  }, [contributing_nodes, posMap, maxContrib, rootId])

  const memoNodeTypes = useMemo(() => nodeTypes, [])

  return (
    <div className="relative h-full w-full" style={{ zIndex: 2 }}>
      {/* Convex hull zone — behind React Flow canvas */}
      <HullZone nodePositions={hullPositions} />

      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={memoNodeTypes}
        fitView
        fitViewOptions={FIT_VIEW_OPTIONS}
        minZoom={0.15}
        maxZoom={2}
        proOptions={PRO_OPTIONS}
        style={{ background: "transparent", zIndex: 1, position: "relative" }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="rgba(0,240,255,0.04)"
        />
        <Controls
          className="!bg-transparent !border-0"
          showInteractive={false}
          onFitView={fitView}
        />
      </ReactFlow>
    </div>
  )
}

// ─── Public component ─────────────────────────────────────────────────────────
interface Props {
  result: BlastRadiusHostResult
  /** Canvas dimensions — parent must set a fixed height */
  width?: number
  height?: number
}

export function BlastRadiusNetworkView({ result, width = 800, height = 460 }: Props) {
  if (result.contributing_nodes.length === 0) {
    return (
      <div
        className="flex h-full min-h-[280px] items-center justify-center rounded-md border border-dashed text-center"
        style={{
          borderColor: "rgba(0,240,255,0.15)",
          color: "rgba(185,202,203,0.4)",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "0.75rem",
        }}
      >
        DATA INSUFFICIENT: <br /> {result.error || `No reachable topology nodes from ${result.host}`}
      </div>
    )
  }

  return (
    <>
      {/* Dash-scroll animation injected once */}
      <style>{`
        @keyframes dash-scroll {
          to { stroke-dashoffset: -40; }
        }
      `}</style>
      <div
        className="h-full w-full overflow-hidden rounded-md"
        style={{
          background: "rgba(5,7,13,0.85)",
          border: "1px solid rgba(0,240,255,0.12)",
          position: "relative",
        }}
      >
        <ReactFlowProvider>
          <BlastGraphInner result={result} canvasW={width} canvasH={height} />
        </ReactFlowProvider>

        {/* Legend */}
        <div
          className="absolute left-2 top-2 z-20 flex flex-col gap-1 rounded px-2 py-1.5"
          style={{
            background: "rgba(12,18,34,0.80)",
            border: "1px solid rgba(0,240,255,0.12)",
            backdropFilter: "blur(10px)",
          }}
        >
          <LegendItem color={COMPROMISED_COLOR} label="compromised host" />
          <LegendItem color="#a855f7" label="high impact" />
          <LegendItem color="#ffb020" label="medium impact" />
          <LegendItem color="rgba(0,240,255,0.6)" label="low impact" />
          <LegendItem color={ZONE_STROKE} label="blast zone" dashed />
        </div>
      </div>
    </>
  )
}

function LegendItem({
  color,
  label,
  dashed,
}: {
  color: string
  label: string
  dashed?: boolean
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span
        style={{
          display: "inline-block",
          width: 20,
          height: dashed ? 0 : 2,
          borderRadius: dashed ? 0 : 1,
          background: dashed ? "none" : color,
          border: dashed ? `1px dashed ${color}` : "none",
          opacity: 0.9,
        }}
      />
      <span
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "0.62rem",
          color: "rgba(185,202,203,0.55)",
          letterSpacing: "0.05em",
        }}
      >
        {label}
      </span>
    </div>
  )
}
