"use client"

import { useCallback, useMemo, useState } from "react"
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
        borderColor: highRisk ? "var(--destructive)" : color,
        boxShadow: selected ? `0 0 0 2px var(--ring)` : highRisk ? `0 0 0 1px var(--destructive)` : undefined,
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

function toFlow(graph: IncidentGraph): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = graph.nodes.map((n: ApiNode) => ({
    id: n.id,
    type: "entity",
    position: n.position,
    data: n.data,
  }))
  const edges: Edge[] = graph.edges.map((e) => {
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
      labelStyle: { fill: "var(--foreground)", fontSize: 9, fontFamily: "var(--font-mono)" },
      labelBgStyle: { fill: "var(--card)", fillOpacity: 0.85 },
      style: { stroke: sevColor, strokeWidth: e.animated ? 2 : 1.4 },
      data: { technique: e.technique_name, evidence: e.evidence_event_ids },
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
  const { nodes, edges } = useMemo(() => toFlow(graph), [graph])
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

  return (
    <div className="relative h-full w-full">
      <ReactFlow
        nodes={nodes.map((n) => ({ ...n, selected: n.id === selectedId }))}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={handleNodeClick}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
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
