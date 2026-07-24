import { useEffect, useMemo, useRef, useState } from 'react'
import {
  fetchStatus,
  fetchTargets,
  fetchRecoveredFiles,
  runPipelineByPath,
  runPipelineByUpload,
  runRamAnalysisByPath,
  runRamAnalysisByUpload,
  runRamSanityByPath,
  runRamSanityByUpload,
  downloadReport,
} from './services/pipelineApi'

const initialForm = {
  image_path: 'evidence/L0_Graphic.dd',
  case_id: 'NIST-TEST-01',
}

function MetricCard({ label, value, hint }) {
  return (
    <article className="min-w-0 rounded-2xl border border-white/10 bg-white/6 p-5 shadow-[0_20px_60px_rgba(0,0,0,0.25)] backdrop-blur">
      <p className="text-xs uppercase tracking-[0.3em] text-cyan-200/80">{label}</p>
      <div className="mt-3 break-all text-2xl font-semibold leading-snug text-white">{value}</div>
      <p className="mt-2 break-words text-sm text-slate-300">{hint}</p>
    </article>
  )
}

const NUMERIC_COLUMN_KEYS = new Set([
  "PID", "PPID", "Handles", "Threads", "Size",
  "offset", "length", "file_size_bytes", "physical_offset_bytes",
  "target_artifacts_count", "files_recovered_count",
  "process_count", "process_tree_count", "network_connection_count",
  "warning_count", "event_id"
])

const TIMESTAMP_COLUMN_KEYS = new Set([
  "CREATETIME", "EXITTIME", "create_time", "exit_time",
  "timestamp", "TimeStamp", "mtime", "created_time",
  "modified_time", "accessed_time"
])

function isNumericColumn(key) {
  return NUMERIC_COLUMN_KEYS.has(key)
}

function isTimestampColumn(key) {
  return TIMESTAMP_COLUMN_KEYS.has(key)
}

function DataTable({ title, rows, emptyText }) {
  return (
    <section className="min-w-0 rounded-3xl border border-white/10 bg-slate-950/70 p-5 shadow-2xl">
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold text-white">{title}</h2>
        <span className="text-sm text-slate-400">{rows.length} rows</span>
      </div>
      {rows.length ? (
        <div className="relative mt-4 w-full overflow-x-auto">
          <table className="w-full divide-y divide-white/10 text-left text-sm">
            <thead className="text-slate-300">
              <tr>
                {Object.keys(rows[0]).map((key) => (
                  <th
                    key={key}
                    className={`px-3 py-2 font-medium uppercase tracking-[0.2em] whitespace-nowrap ${
                      isNumericColumn(key) ? 'text-right' : 'text-left'
                    }`}
                  >
                    {key}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-100">
              {rows.map((row, index) => (
                <tr key={`${title}-${index}`} className={row.match_found ? 'bg-emerald-500/10' : ''}>
                  {Object.keys(row).map((key, cellIndex) => {
                    const value = row[key]
                    const displayValue = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value ?? '')
                    return (
                      <td
                        key={`${index}-${cellIndex}`}
                        className={`px-3 py-2 align-top text-slate-200 ${
                          isNumericColumn(key)
                            ? 'text-right font-mono tabular-nums'
                            : isTimestampColumn(key)
                              ? 'text-left font-mono text-xs whitespace-nowrap'
                              : 'text-left'
                        }`}
                      >
                        {displayValue}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="mt-4 text-sm text-slate-400">{emptyText}</p>
      )}
    </section>
  )
}

function summarizeEvents(events) {
  return (events ?? []).map((event, index) => {
    const details = Object.entries(event.event_data ?? {})
      .slice(0, 4)
      .map(([key, value]) => `${key}=${value}`)
      .join(' | ')

    return {
      id: `${event.record_id ?? event.event_id ?? index}`,
      timestamp: event.timestamp ?? '',
      event_id: event.event_id ?? '',
      provider: event.provider ?? '',
      channel: event.channel ?? '',
      details,
    }
  })
}

function summarizeSessions(sessions) {
  return (sessions ?? []).map((session, index) => ({
    id: `${session.logon_id ?? index}`,
    user: session.user_summary ?? 'Unknown user',
    logon_type: session.logon_type_label ?? 'Unknown',
    logon_time: session.logon_time ?? '',
    logoff_time: session.logoff_time ?? 'Still open',
    source: session.source ?? '',
    attributed_usb_events: (session.attributed_usb_event_indicators ?? []).length,
  }))
}

function LogIntelligencePanel({ logAnalysis }) {
  if (!logAnalysis) {
    return null
  }

  const fileMetadata = logAnalysis.file_metadata ?? {}
  const eventScan = logAnalysis.event_log_scan ?? {}
  const analysisFailed = logAnalysis.ok === false
  const analysisError = logAnalysis.error ?? ''
  const usbRows = summarizeEvents(eventScan.usb_connection_events)
  const transferRows = summarizeEvents(eventScan.file_transfer_events)
  const uploadedRows = summarizeEvents(logAnalysis.uploaded_events)
  const hasNoDetectedEvents =
    !analysisFailed &&
    (eventScan.event_count ?? 0) === 0 &&
    (eventScan.usb_connection_count ?? 0) === 0 &&
    (eventScan.file_transfer_count ?? 0) === 0

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl">
      <div className="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">Log intelligence</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">File metadata and device activity</h2>
        </div>
        <div
          className={`shrink-0 rounded-2xl px-4 py-3 text-sm ${analysisFailed ? 'border border-rose-400/30 bg-rose-500/15 text-rose-100' : 'border border-cyan-300/20 bg-cyan-300/10 text-cyan-100'}`}
        >
          {analysisFailed ? 'Log analysis failed' : 'Log analysis ready'}
        </div>
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="File hash"
          value={(fileMetadata.hash ?? logAnalysis.summary?.source_hash ?? '').slice(0, 16) || 'n/a'}
          hint={fileMetadata.filename ?? logAnalysis.summary?.source_filename ?? 'Uploaded artifact'}
        />
        <MetricCard
          label="File size"
          value={Number(fileMetadata.size ?? logAnalysis.summary?.source_size_bytes ?? 0).toLocaleString()}
          hint={`${fileMetadata.extension ?? 'unknown'} ${fileMetadata.mime_type ? `· ${fileMetadata.mime_type}` : ''}`.trim()}
        />
        <MetricCard
          label="USB events"
          value={eventScan.usb_connection_count ?? 0}
          hint="Potential removable-device connections from the current device logs."
        />
        <MetricCard
          label="Transfer events"
          value={eventScan.file_transfer_count ?? 0}
          hint="Potential file-copy or transfer initialization activity."
        />
      </div>

      <div className="mt-5 grid gap-4 xl:grid-cols-2">
        <div className="min-w-0 rounded-2xl border border-white/10 bg-slate-950/50 p-4 text-sm text-slate-200">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Metadata summary</p>
          <div className="mt-3 grid gap-2">
            <p className="break-all"><span className="text-slate-400">Path:</span> {logAnalysis.artifact_path ?? 'n/a'}</p>
            <p className="break-words"><span className="text-slate-400">Created:</span> {fileMetadata.created_time ?? 'n/a'}</p>
            <p className="break-words"><span className="text-slate-400">Accessed:</span> {fileMetadata.accessed_time ?? 'n/a'}</p>
            <p className="break-words"><span className="text-slate-400">Modified:</span> {fileMetadata.modified_time ?? fileMetadata.mtime ?? 'n/a'}</p>
            <p className="break-words"><span className="text-slate-400">MIME:</span> {fileMetadata.mime_type ?? 'n/a'}</p>
            <p><span className="text-slate-400">Scanned logs:</span> {Array.isArray(eventScan.logs_scanned) ? eventScan.logs_scanned.length : 0}</p>
          </div>
        </div>

        <div className="min-w-0 rounded-2xl border border-white/10 bg-slate-950/50 p-4 text-sm text-slate-200">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Activity summary</p>
          <div className="mt-3 grid gap-2">
            <p><span className="text-slate-400">Uploaded EVTX records:</span> {logAnalysis.uploaded_event_count ?? 0}</p>
            <p><span className="text-slate-400">USB matches:</span> {eventScan.usb_connection_count ?? 0}</p>
            <p><span className="text-slate-400">Transfer matches:</span> {eventScan.file_transfer_count ?? 0}</p>
            <p className="break-words"><span className="text-slate-400">Case ID:</span> {logAnalysis.case_id ?? 'n/a'}</p>
          </div>
          {analysisFailed ? <p className="mt-3 break-words text-rose-100">{analysisError}</p> : null}
          {hasNoDetectedEvents ? (
            <p className="mt-3 text-slate-400">No USB, transfer, registry, prefetch, or browser-history events were found in this run.</p>
          ) : null}
        </div>
      </div>

      <div className="mt-5 grid gap-6 xl:grid-cols-2">
        <DataTable
          title="USB Connection Hits"
          rows={usbRows}
          emptyText="No USB-related events were detected in the current device logs."
        />
        <DataTable
          title="File Transfer Hits"
          rows={transferRows}
          emptyText="No file-transfer initialization events were detected in the current device logs."
        />
      </div>

      {uploadedRows.length ? (
        <div className="mt-6">
          <DataTable
            title="Uploaded EVTX Records"
            rows={uploadedRows}
            emptyText="The uploaded file did not yield any EVTX records."
          />
        </div>
      ) : null}
    </section>
  )
}

function SessionTracePanel({ logAnalysis }) {
  if (!logAnalysis) {
    return null
  }

  const eventScan = logAnalysis.event_log_scan ?? {}
  const sessions = eventScan.logon_sessions ?? []
  const sessionRows = summarizeSessions(sessions)
  const sessionSource = eventScan.session_trace_source ?? 'none'
  const sourceLabel =
    sessionSource === 'security_log'
      ? 'Security.evtx (4624/4634/4647)'
      : sessionSource === 'profile_service_fallback'
        ? 'User Profile Service fallback (2/4)'
        : 'No session data available'

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl">
      <div className="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">Session trace</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">Logged-in users and session windows</h2>
        </div>
        <div className="shrink-0 rounded-2xl border border-cyan-300/20 bg-cyan-300/10 px-4 py-3 text-sm text-cyan-100">
          Source: {sourceLabel}
        </div>
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-2">
        <MetricCard
          label="Sessions found"
          value={eventScan.session_count ?? sessions.length ?? 0}
          hint="Interactive (console) or RDP logon sessions reconstructed from the event logs."
        />
        <MetricCard
          label="USB events attributed"
          value={sessionRows.reduce((total, row) => total + row.attributed_usb_events, 0)}
          hint="USB connection events whose timestamp fell inside a known session window."
        />
      </div>

      <div className="mt-6">
        <DataTable
          title="Logon Sessions"
          rows={sessionRows}
          emptyText="No interactive logon sessions were reconstructed from the available logs."
        />
      </div>
    </section>
  )
}

function RamSanitySection({ sanityReport }) {
  if (!sanityReport) return null

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">RAM sanity</p>
          <h3 className="mt-2 text-2xl font-semibold text-white">Preflight check</h3>
        </div>
        <span className={`rounded-full px-4 py-1.5 text-sm font-semibold ${
          sanityReport.status === 'pass'
            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-400/30'
            : 'bg-amber-500/20 text-amber-300 border border-amber-400/30'
        }`}>
          {sanityReport.status === 'pass' ? 'PASS' : 'FAIL'}
        </span>
      </div>

      <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="File size"
          value={Number(sanityReport.size_bytes ?? 0).toLocaleString()}
          hint={sanityReport.extension_supported ? 'Supported RAM extension' : 'Unsupported extension'}
        />
        <MetricCard
          label="Memory candidate"
          value={sanityReport.likely_memory_capture ? 'YES' : 'NO'}
          hint="Based on extension and size heuristics"
        />
        <MetricCard
          label="Plugin check"
          value={sanityReport.plugin_check?.status ? sanityReport.plugin_check.status.toUpperCase() : 'N/A'}
          hint={sanityReport.plugin_check?.plugin ?? 'windows.info.Info'}
        />
        <MetricCard
          label="Image file"
          value={(sanityReport.image_path ?? '').split(/[\\/]/).pop() || 'n/a'}
          hint={sanityReport.image_path ?? ''}
        />
      </div>

      {Array.isArray(sanityReport?.notes) && sanityReport.notes.length ? (
        <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/50 p-4 text-sm text-slate-200">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Notes</p>
          <ul className="mt-3 space-y-2">
            {sanityReport.notes.map((note, index) => (
              <li key={`sanity-note-${index}`}>• {note}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {sanityReport?.plugin_check?.error ? (
        <div className="mt-4 rounded-2xl border border-amber-400/20 bg-amber-500/10 p-4 text-sm text-amber-100">
          <p className="text-xs uppercase tracking-[0.3em] text-amber-200/80">Plugin error</p>
          <p className="mt-2 break-words">{sanityReport.plugin_check.error}</p>
        </div>
      ) : null}
    </section>
  )
}

function RamAnalysisSection({ analysisReport }) {
  if (!analysisReport) return null

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">RAM analysis</p>
          <h3 className="mt-2 text-2xl font-semibold text-white">Volatility results</h3>
        </div>
        {analysisReport.ok === false ? (
          <span className="rounded-full border border-rose-400/30 bg-rose-500/20 px-4 py-1.5 text-sm font-semibold text-rose-300">
            ERROR
          </span>
        ) : null}
      </div>

      <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Processes"
          value={analysisReport.summary?.process_count ?? analysisReport.processes?.length ?? 0}
          hint="Running process list extracted from memory"
        />
        <MetricCard
          label="Process tree"
          value={analysisReport.summary?.process_tree_count ?? analysisReport.process_tree?.length ?? 0}
          hint="Parent/child relationship view"
        />
        <MetricCard
          label="Network rows"
          value={analysisReport.summary?.network_connection_count ?? analysisReport.network_connections?.length ?? 0}
          hint={analysisReport.network_backend ? `Backend: ${analysisReport.network_backend}` : 'Network plugin output'}
        />
        <MetricCard
          label="Warnings"
          value={analysisReport.summary?.warning_count ?? analysisReport.warnings?.length ?? 0}
          hint="Non-fatal plugin limitations reported here"
        />
      </div>

      {analysisReport.ok === false ? (
        <div className="mt-5 rounded-2xl border border-rose-400/20 bg-rose-500/10 p-4 text-sm text-rose-100">
          <p className="text-xs uppercase tracking-[0.3em] text-rose-200/80">Analysis Error</p>
          <p className="mt-2 break-words">{analysisReport.error}</p>
        </div>
      ) : null}

      {Array.isArray(analysisReport.warnings) && analysisReport.warnings.length ? (
        <div className="mt-5 rounded-2xl border border-amber-400/20 bg-amber-500/10 p-4 text-sm text-amber-100">
          <p className="text-xs uppercase tracking-[0.3em] text-amber-200/80">Warnings</p>
          <ul className="mt-3 space-y-2">
            {analysisReport.warnings.map((warning, index) => (
              <li key={`ram-warning-${index}`}>• {warning}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="mt-6 space-y-6">
        <DataTable
          title="Process List"
          rows={analysisReport.processes ?? []}
          emptyText="No process rows were returned."
        />
        <DataTable
          title="Process Tree"
          rows={analysisReport.process_tree ?? []}
          emptyText="No process tree rows were returned."
        />
        <DataTable
          title="Network Connections"
          rows={analysisReport.network_connections ?? []}
          emptyText="No network rows were returned for this capture."
        />
      </div>
    </section>
  )
}

// ── Report Configuration Form Component ─────────────────────────────────

const INITIAL_REPORT_FORM = {
  case_number: 'SP-2026-XXXX',
  investigator_name: 'Lead Examiner',
  credentials: 'GCFA, SwiftProbe Certified Examiner',
  organization: 'SwiftProbe Forensic Investigations Unit, Banepa, Nepal',
  target_machine: 'DESKTOP-XXXXX (Windows 11)',
  asset_id: 'AST-XXXXX',
  requestor_name: 'Requesting Party',
  requestor_org: 'Client Organization',
  executive_summary: '',
}

function ReportForm({ form, onChange, onGenerate, generating, error, pipelineResult }) {
  const updateField = (field) => (e) => {
    onChange({ ...form, [field]: e.target.value })
  }

  return (
    <div className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">Report Generator</p>
          <h2 className="mt-2 text-3xl font-semibold text-white">Court-Presentable Forensic Report</h2>
          <p className="mt-2 text-sm text-slate-400">
            Configure the case metadata below and generate a professionally formatted PDF report suitable for legal proceedings.
          </p>
        </div>
        <div className="shrink-0">
          <button
            type="button"
            onClick={onGenerate}
            disabled={generating}
            className="rounded-full bg-cyan-400 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {generating ? 'Generating PDF…' : 'Generate & Download Report'}
          </button>
        </div>
      </div>

      {error ? (
        <div className="mt-4 rounded-2xl border border-rose-400/20 bg-rose-500/10 p-4 text-sm text-rose-100">
          {error}
        </div>
      ) : null}

      {pipelineResult ? (
        <div className="mt-4 rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-4 text-sm text-emerald-100">
          Pipeline data available: {pipelineResult.total_files_carved ?? 0} carved files,{' '}
          {pipelineResult.total_matches_found ?? 0} matches. This data will be included in the report.
        </div>
      ) : (
        <div className="mt-4 rounded-2xl border border-amber-400/20 bg-amber-500/10 p-4 text-sm text-amber-100">
          No pipeline data yet. Run the pipeline in the File Carver tab first to include evidence data in the report.
        </div>
      )}

      <div className="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <label className="flex flex-col gap-1.5 text-sm text-slate-300">
          Case Number
          <input value={form.case_number} onChange={updateField('case_number')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300">
          Lead Investigator
          <input value={form.investigator_name} onChange={updateField('investigator_name')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300">
          Credentials
          <input value={form.credentials} onChange={updateField('credentials')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300 lg:col-span-2">
          Organization
          <input value={form.organization} onChange={updateField('organization')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300">
          Asset ID
          <input value={form.asset_id} onChange={updateField('asset_id')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300 lg:col-span-2">
          Target Machine
          <input value={form.target_machine} onChange={updateField('target_machine')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300">
          Requestor Name
          <input value={form.requestor_name} onChange={updateField('requestor_name')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300 lg:col-span-2">
          Requesting Organization
          <input value={form.requestor_org} onChange={updateField('requestor_org')}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm text-slate-300 lg:col-span-3">
          Executive Summary
          <textarea value={form.executive_summary} onChange={updateField('executive_summary')} rows={3}
            className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50 resize-none"
            placeholder="Brief summary of findings for the report..." />
        </label>
      </div>
    </div>
  )
}

export default function App() {
  const [form, setForm] = useState(initialForm)
  const [selectedFile, setSelectedFile] = useState(null)
  const [fileNote, setFileNote] = useState('No file selected yet.')
  const [status, setStatus] = useState(null)
  const [targets, setTargets] = useState([])
  const [recovered, setRecovered] = useState([])
  const [pipeline, setPipeline] = useState(null)
  const [activeTab, setActiveTab] = useState('carver')
  const [runLog, setRunLog] = useState([])
  const [loading, setLoading] = useState(false)
  const [running, setRunning] = useState(false)
  const [ramImagePath, setRamImagePath] = useState('')
  const [ramSelectedFile, setRamSelectedFile] = useState(null)
  const [ramFileNote, setRamFileNote] = useState('No RAM file selected yet.')
  const [ramSanity, setRamSanity] = useState(null)
  const [ramAnalysis, setRamAnalysis] = useState(null)
  const [ramRunning, setRamRunning] = useState(false)
  const ramBusyRef = useRef(false)
  const [reportForm, setReportForm] = useState(INITIAL_REPORT_FORM)
  const [reportGenerating, setReportGenerating] = useState(false)
  const [reportError, setReportError] = useState(null)

  const tabClasses = (tabName) =>
    `rounded-2xl px-5 py-3 text-sm font-semibold transition ${activeTab === tabName ? 'bg-cyan-400 text-slate-950' : 'bg-white/5 text-slate-300 hover:bg-white/10'}`

  const logStage = (message) => {
    setRunLog((current) => [...current, { time: new Date().toLocaleTimeString(), message }])
  }

  const loadDashboard = async () => {
    setLoading(true)
    try {
      const [statusJson, targetsJson, recoveredJson] = await Promise.all([
        fetchStatus(),
        fetchTargets(),
        fetchRecoveredFiles(form.case_id),
      ])

      setStatus(statusJson)
      setTargets(targetsJson.items ?? [])
      setRecovered(recoveredJson.items ?? [])
    } catch (error) {
      setStatus({ ok: false, backend_unreachable: true, error: error.message })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDashboard()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const metrics = useMemo(() => {
    const matches = recovered.filter((item) => item.match_found).length
    return [
      { label: 'Target hashes', value: targets.length, hint: 'Known fingerprints loaded from Supabase.' },
      { label: 'Recovered rows', value: recovered.length, hint: 'Records for the selected case ID.' },
      { label: 'Matches found', value: pipeline?.total_matches_found ?? matches, hint: 'Positive hash matches in the current set.' },
      { label: 'Database sync', value: pipeline?.database_sync_status ?? (status?.supabase_configured ? 'ready' : 'offline'), hint: 'Supabase connection state for the API.' },
    ]
  }, [targets.length, recovered, pipeline, status])

  const logAnalysis = pipeline?.log_analysis ?? null

  const runPipeline = async (event) => {
    event.preventDefault()
    setRunning(true)
    setPipeline(null)
    setActiveTab('log')
    setRunLog([])

    try {
      logStage(selectedFile ? 'Uploading selected evidence file to Flask.' : 'Using the local image path directly.')

      const result = selectedFile
        ? await runPipelineByUpload({ caseId: form.case_id, file: selectedFile })
        : await runPipelineByPath({ caseId: form.case_id, imagePath: form.image_path })

      setPipeline(result)
      logStage('Pipeline finished and the dashboard data was refreshed.')
      if (result.ok) {
        await loadDashboard()
      }
    } catch (error) {
      setPipeline({ ok: false, error: error.message })
      logStage(`Pipeline failed: ${error.message}`)
    } finally {
      setRunning(false)
    }
  }

  const runRamAction = async (runner, successMessage) => {
    if (ramBusyRef.current) return
    ramBusyRef.current = true
    setRamRunning(true)
    try {
      const result = ramSelectedFile
        ? await runner({ caseId: form.case_id, file: ramSelectedFile })
        : await runner({ caseId: form.case_id, imagePath: ramImagePath })

      if (result?.stored_path) {
        setRamImagePath(result.stored_path)
      } else if (result?.image_path) {
        setRamImagePath(result.image_path)
      }

      if (runner === runRamSanityByUpload || runner === runRamSanityByPath) {
        setRamSanity(result)
      } else {
        setRamAnalysis(result)
      }

      logStage(successMessage)
      await loadDashboard()
      return result
    } catch (error) {
      const payload = { ok: false, error: error.message }
      if (runner === runRamSanityByUpload || runner === runRamSanityByPath) {
        setRamSanity(payload)
      } else {
        setRamAnalysis(payload)
      }
      logStage(`RAM analysis failed: ${error.message}`)
      return payload
    } finally {
      setRamRunning(false)
      ramBusyRef.current = false
    }
  }

  const runRamSanityCheck = () => {
    return runRamAction(
      ramSelectedFile ? runRamSanityByUpload : runRamSanityByPath,
      'RAM sanity check completed.'
    )
  }

  const runRamAnalysis = () => {
    return runRamAction(
      ramSelectedFile ? runRamAnalysisByUpload : runRamAnalysisByPath,
      'RAM analysis completed.'
    )
  }

  const generateAndDownloadReport = async () => {
    setReportGenerating(true)
    setReportError(null)
    try {
      const caseMeta = {
        ...reportForm,
        case_id: form.case_id,
        date_of_analysis: new Date().toISOString().split('T')[0],
        report_date: new Date().toISOString().split('T')[0],
        doc_control_id: `${reportForm.case_number}-R1`,
        pipeline_result: pipeline || undefined,
      }
      const result = await downloadReport(caseMeta)
      logStage(`Report downloaded: ${result.filename}`)
    } catch (error) {
      setReportError(error.message)
      logStage(`Report generation failed: ${error.message}`)
    } finally {
      setReportGenerating(false)
    }
  }

  const statusText = status?.backend_unreachable
    ? 'Backend unavailable'
    : status?.supabase_configured
      ? 'Supabase configured'
      : 'Supabase not configured'

  const handleFileChange = (event) => {
    const file = event.target.files?.[0] ?? null
    setSelectedFile(file)
    setFileNote(file ? `${file.name} · ${(file.size / (1024 * 1024)).toFixed(2)} MB` : 'No file selected yet.')
  }

  const handleRamFileChange = (event) => {
    const file = event.target.files?.[0] ?? null
    setRamSelectedFile(file)
    setRamFileNote(file ? `${file.name} · ${(file.size / (1024 * 1024)).toFixed(2)} MB` : 'No RAM file selected yet.')
    setRamSanity(null)
    setRamAnalysis(null)
    if (file) {
      setRamImagePath('')
    }
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.18),_transparent_42%),linear-gradient(180deg,#020617_0%,#07111f_48%,#020617_100%)] text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-8 px-6 py-8 lg:px-10">
        <header className="overflow-hidden rounded-[2rem] border border-white/10 bg-white/5 p-8 shadow-[0_30px_100px_rgba(0,0,0,0.35)] backdrop-blur">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="min-w-0">
              <p className="text-xs uppercase tracking-[0.45em] text-cyan-200/80">SwiftProbe</p>
              <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white lg:text-5xl">Evidence pipeline dashboard</h1>
              <p className="mt-4 max-w-3xl text-base leading-7 text-slate-300">
                Trigger the forensic pipeline, review target hashes, and inspect recovered files from a single app surface.
              </p>
            </div>
            <div className="shrink-0 rounded-2xl border border-cyan-300/20 bg-cyan-300/10 px-4 py-3 text-sm text-cyan-100">
              {loading
                ? 'Refreshing dashboard…'
                : status?.backend_unreachable
                  ? 'Backend unavailable'
                  : statusText}
            </div>
          </div>
        </header>

        <section className="flex flex-wrap gap-3 rounded-3xl border border-white/10 bg-slate-950/70 p-3 shadow-2xl">
          <button type="button" onClick={() => setActiveTab('carver')} className={tabClasses('carver')}>
            File Carver
          </button>
          <button type="button" onClick={() => setActiveTab('ram')} className={tabClasses('ram')}>
            RAM Module
          </button>
          <button type="button" onClick={() => setActiveTab('log')} className={tabClasses('log')}>
            Log Module
          </button>
          <button type="button" onClick={() => setActiveTab('report')} className={tabClasses('report')}>
            Generate Report
          </button>
        </section>

        {activeTab === 'carver' ? (
          <>
            <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {metrics.map((metric) => (
                <MetricCard key={metric.label} {...metric} />
              ))}
            </section>
            <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
              <form onSubmit={runPipeline} className="min-w-0 rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <h2 className="text-2xl font-semibold text-white">Run evidence pipeline</h2>
                    <p className="mt-2 text-sm text-slate-400">
                      Upload a raw image or use a local path, then hash, carve, compare against targets, and persist recovered rows.
                    </p>
                  </div>
                  <button type="submit" disabled={running}
                    className="shrink-0 rounded-full bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60">
                    {running ? 'Running…' : 'Run Pipeline'}
                  </button>
                </div>
                <div className="mt-6 grid gap-4 md:grid-cols-2">
                  <label className="flex flex-col gap-2 text-sm text-slate-300">
                    Image path
                    <input value={form.image_path} onChange={(e) => setForm((c) => ({ ...c, image_path: e.target.value }))}
                      className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
                  </label>
                  <label className="flex flex-col gap-2 text-sm text-slate-300">
                    Case ID
                    <input value={form.case_id} onChange={(e) => setForm((c) => ({ ...c, case_id: e.target.value }))}
                      className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
                  </label>
                </div>
                <label className="mt-4 flex cursor-pointer flex-col gap-3 rounded-[1.5rem] border border-dashed border-cyan-300/30 bg-cyan-300/5 p-5 text-sm text-slate-300 transition hover:border-cyan-300/60 hover:bg-cyan-300/10">
                  <span className="text-xs uppercase tracking-[0.3em] text-cyan-200/80">Evidence file upload</span>
                  <span className="text-base text-white">Choose a raw image from your device</span>
                  <span className="break-words text-slate-400">{fileNote}</span>
                  <input type="file" className="hidden" onChange={handleFileChange} accept=".dd,.raw,.img,.bin,.e01,.evtx" />
                </label>
                {pipeline ? (
                  <div className={`mt-6 rounded-2xl border p-4 ${pipeline.ok ? 'border-emerald-400/20 bg-emerald-500/10' : 'border-rose-400/20 bg-rose-500/10'}`}>
                    <p className="text-sm uppercase tracking-[0.35em] text-slate-300">Latest pipeline result</p>
                    <div className="mt-3 grid gap-3 sm:grid-cols-3">
                      <div><p className="text-xs text-slate-400">Total carved</p><p className="text-2xl font-semibold text-white">{pipeline.total_files_carved ?? 0}</p></div>
                      <div><p className="text-xs text-slate-400">Matches found</p><p className="text-2xl font-semibold text-white">{pipeline.total_matches_found ?? 0}</p></div>
                      <div><p className="text-xs text-slate-400">Sync status</p><p className="break-words text-2xl font-semibold text-white">{pipeline.database_sync_status ?? 'unknown'}</p></div>
                    </div>
                    {pipeline.source_image_hash ? (
                      <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/40 p-4 text-sm text-slate-200">
                        <p className="break-all"><span className="text-slate-400">Source hash:</span> {pipeline.source_image_hash}</p>
                      </div>
                    ) : null}
                    {pipeline.error ? <p className="mt-4 break-words text-sm text-rose-100">{pipeline.error}</p> : null}
                  </div>
                ) : null}
              </form>
              <section className="min-w-0 rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl">
                <h2 className="text-2xl font-semibold text-white">Operational guidance</h2>
                <div className="mt-4 space-y-4 text-sm leading-7 text-slate-300">
                  <p>1. Load target hashes into Supabase using the schema from sql.md.</p>
                  <p>2. Keep raw evidence in ignored folders and run the pipeline against a local image copy.</p>
                  <p>3. Use this dashboard to confirm source hash, inspect matches, and review recovered rows.</p>
                  <p>4. After the pipeline completes, switch to the Generate Report tab to produce a court-ready PDF.</p>
                </div>
              </section>
            </section>
            <section className="grid gap-6 xl:grid-cols-2">
              <DataTable title="Target Artifacts" rows={targets} emptyText="No target hashes returned." />
              <DataTable title={`Recovered Files${form.case_id ? ` — ${form.case_id}` : ''}`} rows={recovered} emptyText="No recovered files loaded yet." />
            </section>
          </>
        ) : activeTab === 'ram' ? (
          <section className="flex flex-col gap-8">
            <div className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl">
              <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">RAM module</p>
              <h2 className="mt-3 text-3xl font-semibold text-white">Volatile memory analysis</h2>
              <p className="mt-4 text-sm leading-7 text-slate-400">
                Run a sanity check first, then analyze a RAM capture for processes, process trees, and network artifacts.
              </p>
              <div className="mt-6 grid gap-4 sm:grid-cols-3">
                <label className="flex flex-col gap-2 text-sm text-slate-300 sm:col-span-2">
                  Case ID
                  <input value={form.case_id} onChange={(e) => setForm((c) => ({ ...c, case_id: e.target.value }))}
                    className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
                </label>
                <div className="flex items-end justify-end gap-3 sm:col-span-1">
                  <button type="button" onClick={runRamSanityCheck} disabled={ramRunning}
                    className="rounded-full bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-300 disabled:opacity-60">
                    {ramRunning ? 'Running…' : 'Sanity Check'}
                  </button>
                  <button type="button" onClick={runRamAnalysis} disabled={ramRunning}
                    className="rounded-full border border-white/10 bg-white/5 px-5 py-3 text-sm font-semibold text-white hover:bg-white/10 disabled:opacity-60">
                    {ramRunning ? 'Running…' : 'Analyze'}
                  </button>
                </div>
              </div>
              <label className="mt-4 flex flex-col gap-2 text-sm text-slate-300">
                RAM image path
                <input value={ramImagePath} onChange={(e) => setRamImagePath(e.target.value)}
                  placeholder="Enter a file path or upload a file below"
                  className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none focus:border-cyan-300/50" />
              </label>
              <label className="mt-6 flex cursor-pointer flex-col gap-3 rounded-[1.5rem] border border-dashed border-cyan-300/30 bg-cyan-300/5 p-5 text-sm text-slate-300 hover:border-cyan-300/60 hover:bg-cyan-300/10">
                <span className="text-xs uppercase tracking-[0.3em] text-cyan-200/80">RAM capture upload</span>
                <span className="text-base text-white">Choose a memory image</span>
                <span className="text-slate-400">{ramFileNote}</span>
                <input type="file" className="hidden" onChange={handleRamFileChange} accept=".raw,.mem,.dmp,.vmem,.lime,.aff4,.mddramimage" />
              </label>
            </div>
            <RamSanitySection sanityReport={ramSanity?.report ?? ramSanity} />
            <RamAnalysisSection analysisReport={ramAnalysis} />
          </section>
        ) : activeTab === 'log' ? (
          <section className="grid gap-6 xl:grid-cols-2">
            <div className="min-w-0 rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl xl:col-span-2">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">Log module</p>
                  <h2 className="mt-2 text-3xl font-semibold text-white">File metadata and device activity</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    Log analysis from the latest pipeline run: EVTX parsing, USB detection, file-transfer hints, and session traces.
                  </p>
                </div>
                <button type="button" onClick={() => setActiveTab('carver')}
                  className="shrink-0 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-200 hover:bg-white/10">
                  Open File Carver
                </button>
              </div>
            </div>
            <div className="xl:col-span-2"><LogIntelligencePanel logAnalysis={logAnalysis} /></div>
            <div className="xl:col-span-2"><SessionTracePanel logAnalysis={logAnalysis} /></div>
            <section className="min-w-0 rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl xl:col-span-2">
              <h3 className="text-lg font-semibold text-white">Run log</h3>
              <div className="mt-4 space-y-3">
                {runLog.length ? runLog.map((entry, i) => (
                  <div key={`${entry.time}-${i}`} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-slate-200">
                    <p className="text-xs uppercase tracking-[0.25em] text-slate-400">{entry.time}</p>
                    <p className="mt-1 break-words">{entry.message}</p>
                  </div>
                )) : (
                  <p className="text-sm text-slate-400">No run events yet. Use the File Carver tab to run the pipeline.</p>
                )}
              </div>
            </section>
          </section>
        ) : (
          // ── Report Generator Tab ──
          <section className="flex flex-col gap-6">
            <ReportForm
              form={reportForm}
              onChange={setReportForm}
              onGenerate={generateAndDownloadReport}
              generating={reportGenerating}
              error={reportError}
              pipelineResult={pipeline}
            />
            <section className="min-w-0 rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl">
              <h3 className="text-lg font-semibold text-white">Run log</h3>
              <div className="mt-4 space-y-3">
                {runLog.length ? runLog.map((entry, i) => (
                  <div key={`${entry.time}-${i}`} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-slate-200">
                    <p className="text-xs uppercase tracking-[0.25em] text-slate-400">{entry.time}</p>
                    <p className="mt-1 break-words">{entry.message}</p>
                  </div>
                )) : (
                  <p className="text-sm text-slate-400">No run events yet.</p>
                )}
              </div>
            </section>
          </section>
        )}
      </div>
    </main>
  )
}