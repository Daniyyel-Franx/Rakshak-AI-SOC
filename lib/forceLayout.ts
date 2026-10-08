/**
 * forceLayout.ts — d3-force physics layout utility for BlastRadiusNetworkView.
 *
 * This module is layout-ONLY. It runs a d3-force simulation to convergence
 * and returns final {id, x, y} positions. Rendering is done by React Flow
 * (keeping its native zoom/pan/interaction), NOT by d3's DOM renderer.
 *
 * New deps deliberately added (not duplicating any existing d3 package):
 *   d3-force  — forceManyBody, forceLink, forceCenter, forceCollide
 *   d3-polygon — polygonHull for blast-radius zone SVG path
 *
 * These are exposed only from this module and BlastRadiusNetworkView.tsx;
 * nothing else in the app imports d3.
 */

import {
  forceSimulation,
  forceManyBody,
  forceLink,
  forceCenter,
  forceCollide,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force"

export interface LayoutNode {
  id: string
  [key: string]: unknown
}

export interface LayoutEdge {
  source: string
  target: string
}

export interface LayoutResult {
  id: string
  x: number
  y: number
}

/**
 * runForceLayout — synchronously ticks the simulation to convergence and
 * returns final node positions. Safe to call outside a browser context
 * (no DOM access, purely numerical).
 *
 * @param nodes   Nodes with at minimum an `id` field.
 * @param edges   Directed edges as {source: id, target: id}.
 * @param width   Canvas width for centering. Default 800.
 * @param height  Canvas height for centering. Default 600.
 * @returns       Array of {id, x, y} in canvas coordinates.
 */
export function runForceLayout(
  nodes: LayoutNode[],
  edges: LayoutEdge[],
  width = 800,
  height = 600,
): LayoutResult[] {
  if (nodes.length === 0) return []

  // d3 mutates the node objects with x/y during simulation
  type D3Node = SimulationNodeDatum & { id: string }
  const d3Nodes: D3Node[] = nodes.map((n) => ({ id: n.id }))

  // Build an id→index map for link resolution
  const idToIndex = new Map(d3Nodes.map((n, i) => [n.id, i]))

  type D3Link = SimulationLinkDatum<D3Node> & { _source: string; _target: string }
  const d3Links: D3Link[] = edges
    .filter((e) => idToIndex.has(e.source) && idToIndex.has(e.target))
    .map((e) => ({
      source: idToIndex.get(e.source)!,
      target: idToIndex.get(e.target)!,
      _source: e.source,
      _target: e.target,
    }))

  const sim = forceSimulation<D3Node>(d3Nodes)
    .force("charge", forceManyBody<D3Node>().strength(-220))
    .force(
      "link",
      forceLink<D3Node, D3Link>(d3Links).distance(160).strength(0.7),
    )
    .force("center", forceCenter(width / 2, height / 2))
    .force("collide", forceCollide<D3Node>(60))
    .stop()

  // Run to approximate convergence (alpha ≈ 0)
  // alphaDecay default ~0.0228, so 300 ticks is well past convergence
  const TICKS = 300
  for (let i = 0; i < TICKS; i++) {
    sim.tick()
  }

  return d3Nodes.map((n) => ({
    id: n.id,
    x: n.x ?? width / 2,
    y: n.y ?? height / 2,
  }))
}
