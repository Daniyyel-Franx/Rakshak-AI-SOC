"use client"

import { useCallback, useMemo, useRef, useState } from "react"
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
  ReactFlowProvider,
  useReactFlow,
} from "reactflow"
import {
  Server,
  User,
  Cpu,
  FileWarning,
  Bug,
  Network,
  Building2,
  ShieldAlert,
  HardDrive,
  Boxes,
  Crosshair,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import type { IncidentGraph, GraphNode as ApiNode, SeverityLevel } from "@/lib/types"
import { entityColor, fmtTime } from "@/lib/ui"

const ICONS: Record<string, typeof Server> = {
  attacker_ip: Network,
  user: User,
  source_host: HardDrive,
  target_host: Server,
  process: Cpu,
  service: Boxes,
  file: FileWarning,
  payload: Bug,
  decoy: ShieldAlert,
  site: Building2,
  incident: Crosshair,
}

const SEV_RANK: Record<SeverityLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 }

function EntityNode({ data, selected }: NodeProps) {
  const type = data.entity_type as string
  const sev = data.severity as SeverityLevel
  const Icon = ICONS[type] ?? Server
  const color = entityColor(type)
  const highRisk = SEV_RANK[sev] >= SEV_RANK.high
  return (
    <div
      className="flex min-w-[120px] max-w-[180px] flex-col items-center gap-1 rounded-md border bg-card px-3 py-2 text-center shadow-sm transition-colors"
      style={{
        borderColor: color,
        boxShadow: selected 
          ? `0 0 0 2px var(--ring), 0 0 12px ${color}40` 
          : highRisk 
            ? `0 0 0 1px ${color}80, 0 0 8px ${color}30` 
            : undefined,
      }}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground" />
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground" />
      <div className="flex items-center gap-1.5">
        <Icon className="h-3.5 w-3.5" style={{ color }} aria-hidden />
        <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
          {type.replace(/_/g, " ")}
        </span>
      </div>
      <span className="text-pretty font-mono text-xs text-foreground">{data.label as string}</span>
      {highRisk ? (
        <span className="text-[9px] font-semibold uppercase" style={{ color: "var(--destructive)" }}>
          high risk
        </span>
      ) : null}
    </div>
  )
}

const nodeTypes = { entity: EntityNode }
const FIT_VIEW_OPTIONS = { padding: 0.2 }
const PRO_OPTIONS = { hideAttribution: true }

import { getSmoothStepPath, BaseEdge, EdgeLabelRenderer, type EdgeProps } from "reactflow"

import { useStore } from "reactflow"

interface LabelBox {
  x0: number
  y0: number
  x1: number
  y1: number
}

function CustomEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  data,
  label,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const nodes = useStore((s) => s.getNodes())
  const registry = data?.labelRegistry as React.MutableRefObject<LabelBox[]> | undefined
  
  // Calculate perpendicular normal and tangent along the edge
  const dx = targetX - sourceX
  const dy = targetY - sourceY
  const len = Math.sqrt(dx * dx + dy * dy) || 1
  const nx = -dy / len
  const ny = dx / len
  const tx = dx / len
  const ty = dy / len

  const idx = data?.index || 0
  const isParallel = idx > 0
  
  // Abbreviate repeated "correlated" if cluster is dense or edge is short
  const isCorrelated = label === "correlated"
  const textLabel = isCorrelated && len < 160 ? "corr." : (label as string)

  // Conservative label dimensions based on text length + padding
  const estW = Math.max(textLabel.length * 6.5 + 14, 38)
  const estH = 18

  // Directional preference for parallel edges
  const preferredPerp = isParallel
    ? (idx % 2 === 1 ? -1 : 1) * Math.ceil(idx / 2) * 24
    : 0

  // Perpendicular candidates
  const perpOffsets = isParallel
    ? [
        preferredPerp,
        preferredPerp * 1.4,
        preferredPerp * 0.7,
        preferredPerp > 0 ? preferredPerp + 32 : preferredPerp - 32,
        -preferredPerp * 0.8,
        28,
        -28,
        42,
        -42,
        56,
        -56,
      ]
    : [
        14,
        -14,
        28,
        -28,
        42,
        -42,
        56,
        -56,
        0,
      ]

  // Tangential shifts along the edge (to move away from source/target nodes)
  const maxShift = Math.max(0, Math.min(len * 0.35, 60))
  const tangShifts = [
    0,
    maxShift * 0.5,
    -maxShift * 0.5,
    maxShift,
    -maxShift,
  ]

  const { finalOffsetX, finalOffsetY } = useMemo(() => {
    let bestCx = labelX
    let bestCy = labelY
    let bestScore = Infinity

    const placedLabels = registry?.current || []

    for (const perp of perpOffsets) {
      for (const shift of tangShifts) {
        const cx = labelX + perp * nx + shift * tx
        const cy = labelY + perp * ny + shift * ty
        const cb: LabelBox = {
          x0: cx - estW / 2,
          y0: cy - estH / 2,
          x1: cx + estW / 2,
          y1: cy + estH / 2,
        }

        let penalty = 0

        // 1. Collision with any node rectangle
        for (const node of nodes) {
          const nw = node.width || 150
          const nh = node.height || 60
          const nxPos = node.positionAbsolute?.x ?? node.position.x
          const nyPos = node.positionAbsolute?.y ?? node.position.y
          const nb: LabelBox = {
            x0: nxPos - 4,
            y0: nyPos - 4,
            x1: nxPos + nw + 4,
            y1: nyPos + nh + 4,
          }

          const overlapX = Math.max(0, Math.min(cb.x1, nb.x1) - Math.max(cb.x0, nb.x0))
          const overlapY = Math.max(0, Math.min(cb.y1, nb.y1) - Math.max(cb.y0, nb.y0))
          if (overlapX > 0 && overlapY > 0) {
            penalty += 20000 + overlapX * overlapY * 15
          }
        }

        // 2. Collision with already placed edge labels
        for (const ob of placedLabels) {
          const overlapX = Math.max(0, Math.min(cb.x1, ob.x1) - Math.max(cb.x0, ob.x0))
          const overlapY = Math.max(0, Math.min(cb.y1, ob.y1) - Math.max(cb.y0, ob.y0))
          if (overlapX > 0 && overlapY > 0) {
            penalty += 10000 + overlapX * overlapY * 20
          }
        }

        // 3. Distance penalty
        const distFromCenter = Math.hypot(perp, shift)
        penalty += distFromCenter * 0.4

        // 4. Parallel preference
        if (isParallel) {
          penalty += Math.abs(perp - preferredPerp) * 1.5
        } else {
          penalty += Math.abs(Math.abs(perp) - 14) * 0.5
        }

        if (penalty < bestScore) {
          bestScore = penalty
          bestCx = cx
          bestCy = cy
        }
      }
    }

    if (registry?.current) {
      registry.current.push({
        x0: bestCx - estW / 2,
        y0: bestCy - estH / 2,
        x1: bestCx + estW / 2,
        y1: bestCy + estH / 2,
      })
    }

    return {
      finalOffsetX: bestCx - labelX,
      finalOffsetY: bestCy - labelY,
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceX, sourceY, targetX, targetY, labelX, labelY, id, textLabel])

  return (
    <>
      <BaseEdge id={id} path={edgePath} markerEnd={markerEnd} style={style} />
      {label && (
        <EdgeLabelRenderer>
          <div
            title={label as string}
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX + finalOffsetX}px,${labelY + finalOffsetY}px)`,
              pointerEvents: "auto",
              fontSize: 9,
              fontFamily: "var(--font-mono)",
              background: "rgba(12, 18, 34, 0.95)",
              color: "#e1e2ec",
              padding: "2px 4px",
              borderRadius: 4,
              border: "1px solid rgba(0, 240, 255, 0.3)",
              whiteSpace: "nowrap",
              zIndex: 1000,
            }}
            className="nodrag nopan"
          >
            {textLabel}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}

const edgeTypes = { customEdge: CustomEdge }

function toFlow(
  graph: IncidentGraph,
  labelRegistryRef?: React.MutableRefObject<LabelBox[]>
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = graph.nodes.map((n: ApiNode) => ({
    id: n.id,
    type: "entity",
    position: n.position,
    data: n.data,
  }))
  
  // Group edges by their undirected pair to count parallel edges
  const pairCounts: Record<string, number> = {}
  
  const edges: Edge[] = graph.edges.map((e) => {
    const pair = [e.source, e.target].sort().join("|")
    const index = pairCounts[pair] || 0
    pairCounts[pair] = index + 1

    const sevColor =
      SEV_RANK[e.severity] >= SEV_RANK.high
        ? "var(--chart-3)"
        : e.severity === "medium"
          ? "var(--chart-2)"
          : "var(--muted-foreground)"
    const label = e.technique_id
      ? `${e.technique_id} · ${fmtTime(e.timestamp)}`
      : e.timestamp
        ? `${e.label} · ${fmtTime(e.timestamp)}`
        : e.label
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label,
      animated: e.animated,
      type: "customEdge",
      style: { stroke: sevColor, strokeWidth: e.animated ? 2 : 1.4 },
      data: {
        technique: e.technique_name,
        evidence: e.evidence_event_ids,
        index,
        labelRegistry: labelRegistryRef,
      },
    }
  })
  return { nodes, edges }
}

function LegendItem({ label, color }: { label: string; color: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} aria-hidden />
      <span className="text-[10px] text-muted-foreground">{label}</span>
    </div>
  )
}

function GraphInner({ graph, onSelectNode }: { graph: IncidentGraph; onSelectNode?: (n: ApiNode | null) => void }) {
  const labelRegistryRef = useRef<LabelBox[]>([])
  labelRegistryRef.current = []

  const { nodes, edges } = useMemo(() => toFlow(graph, labelRegistryRef), [graph])
  const rf = useReactFlow()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const handleNodeClick = useCallback(
    (_: unknown, node: Node) => {
      setSelectedId(node.id)
      const apiNode = graph.nodes.find((n) => n.id === node.id) ?? null
      onSelectNode?.(apiNode)
    },
    [graph.nodes, onSelectNode],
  )

  const reset = useCallback(() => {
    setSelectedId(null)
    onSelectNode?.(null)
    rf.fitView({ padding: 0.2, duration: 400 })
  }, [rf, onSelectNode])

    const memoNodeTypes = useMemo(() => nodeTypes, [])
    const memoEdgeTypes = useMemo(() => edgeTypes, [])
    const selectedNodes = useMemo(() => nodes.map((n) => ({ ...n, selected: n.id === selectedId })), [nodes, selectedId])

  return (
    <div className="relative h-full w-full">
      <ReactFlow
        nodes={selectedNodes}
        edges={edges}
        nodeTypes={memoNodeTypes}
        edgeTypes={memoEdgeTypes}
        onNodeClick={handleNodeClick}
        fitView
        fitViewOptions={FIT_VIEW_OPTIONS}
        minZoom={0.2}
        maxZoom={2}
        proOptions={PRO_OPTIONS}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="var(--border)" />
        <Controls className="!bg-card !border-border" showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          nodeStrokeWidth={3}
          nodeColor={(n) => entityColor((n.data as { entity_type: string }).entity_type)}
          nodeBorderRadius={4}
          maskColor="rgba(11, 18, 32, 0.6)"
          style={{ backgroundColor: "var(--card)" }}
        />
      </ReactFlow>
      <div className="absolute left-2 top-2 z-10 flex flex-wrap gap-x-3 gap-y-1 rounded-md border bg-card/90 px-2 py-1.5 backdrop-blur">
        <LegendItem label="attacker" color="var(--chart-3)" />
        <LegendItem label="host" color="var(--chart-1)" />
        <LegendItem label="user/proc" color="var(--chart-2)" />
        <LegendItem label="payload" color="var(--destructive)" />
        <LegendItem label="decoy" color="var(--chart-4)" />
        <LegendItem label="site/zone" color="var(--chart-5)" />
      </div>
      <Button
        size="sm"
        variant="secondary"
        className="absolute right-2 top-2 z-10 h-7 text-xs"
        onClick={reset}
      >
        Reset graph
      </Button>
    </div>
  )
}

export function AttackPathGraph({
  graph,
  onSelectNode,
}: {
  graph: IncidentGraph | undefined
  onSelectNode?: (n: ApiNode | null) => void
}) {
  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="flex h-full min-h-[320px] items-center justify-center rounded-md border border-dashed text-sm text-muted-foreground">
        No attack path yet. Replay a scenario to construct the graph.
      </div>
    )
  }
  return (
    <div className="h-full min-h-[420px] w-full overflow-hidden rounded-md border">
      <ReactFlowProvider>
        <GraphInner graph={graph} onSelectNode={onSelectNode} />
        <span className="sr-only">
          Attack path graph with {graph.nodes.length} nodes and {graph.edges.length} edges.
        </span>
      </ReactFlowProvider>
    </div>
  )
}

export { type SeverityLevel }
