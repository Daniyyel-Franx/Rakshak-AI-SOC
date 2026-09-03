"use client"

import useSWR from "swr"
import { useEffect, useState } from "react"
import * as api from "./api"
import { getMode, onModeChange } from "./api"
import type { ConnectionMode } from "./types"

const POLL = 5000

export function useHealth() {
  return useSWR("health", api.getHealth, { refreshInterval: POLL })
}
export function useScenarios() {
  return useSWR("scenarios", api.getScenarios)
}
export function useTelemetry(limit = 60) {
  return useSWR(["telemetry", limit], () => api.getTelemetry(limit), { refreshInterval: POLL })
}
export function useIncidents() {
  return useSWR("incidents", api.getIncidents, { refreshInterval: POLL })
}
export function useIncident(id: string | null) {
  return useSWR(id ? ["incident", id] : null, () => api.getIncident(id as string))
}
export function useMetrics() {
  return useSWR("metrics", api.getMetrics, { refreshInterval: POLL })
}
export function useLinkStatus() {
  return useSWR("link-status", api.getLinkStatus, { refreshInterval: POLL })
}

// Track live/seeded connection mode reported by the api client.
export function useConnectionMode(): ConnectionMode {
  const [mode, setMode] = useState<ConnectionMode>(getMode())
  useEffect(() => {
    const unsub = onModeChange(setMode)
    return () => {
      unsub()
    }
  }, [])
  return mode
}
