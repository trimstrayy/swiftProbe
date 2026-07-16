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
} from './services/pipelineApi'

const initialForm = {
  image_path: 'evidence/L0_Graphic.dd',
  case_id: 'NIST-TEST-01',
}

function MetricCard({ label, value, hint }) {
  return (
    <article className="rounded-2xl border border-white/10 bg-white/6 p-5 shadow-[0_20px_60px_rgba(0,0,0,0.25)] backdrop-blur">
      <p className="text-xs uppercase tracking-[0.3em] text-cyan-200/80">{label}</p>
      <div className="mt-3 text-3xl font-semibold text-white">{value}</div>
      <p className="mt-2 truncate text-sm text-slate-300" title={hint}>{hint}</p>
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
    <section className="rounded-3xl border border-white/10 bg-slate-950/70 p-5 shadow-2xl">
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

function LogIntelligencePanel({ logAnalysis }) {
  if (!logAnalysis) {
    return null
  }

  const fileMetadata = logAnalysis.file_metadata ?? {}
  const eventScan = logAnalysis.event_log_scan ?? {}
  const usbRows = summarizeEvents(eventScan.usb_connection_events)
  const transferRows = summarizeEvents(eventScan.file_transfer_events)
  const uploadedRows = summarizeEvents(logAnalysis.uploaded_events)

  return (
    <section className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl">
      <div className="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">Log intelligence</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">File metadata and device activity</h2>
        </div>
        <div className="rounded-2xl border border-cyan-300/20 bg-cyan-300/10 px-4 py-3 text-sm text-cyan-100">
          {logAnalysis.error ? 'Log analysis fallback used' : 'Log analysis ready'}
        </div>
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="File hash"
          value={(fileMetadata.hash ?? logAnalysis.summary?.source_hash ?? '').slice(0, 12) || 'n/a'}
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
        <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4 text-sm text-slate-200">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Metadata summary</p>
          <div className="mt-3 grid gap-2">
            <p><span className="text-slate-400">Path:</span> {logAnalysis.artifact_path ?? 'n/a'}</p>
            <p><span className="text-slate-400">Created:</span> {fileMetadata.created_time ?? 'n/a'}</p>
            <p><span className="text-slate-400">Accessed:</span> {fileMetadata.accessed_time ?? 'n/a'}</p>
            <p><span className="text-slate-400">Modified:</span> {fileMetadata.modified_time ?? fileMetadata.mtime ?? 'n/a'}</p>
            <p><span className="text-slate-400">MIME:</span> {fileMetadata.mime_type ?? 'n/a'}</p>
            <p><span className="text-slate-400">Scanned logs:</span> {Array.isArray(eventScan.logs_scanned) ? eventScan.logs_scanned.length : 0}</p>
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4 text-sm text-slate-200">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Activity summary</p>
          <div className="mt-3 grid gap-2">
            <p><span className="text-slate-400">Uploaded EVTX records:</span> {logAnalysis.uploaded_event_count ?? 0}</p>
            <p><span className="text-slate-400">USB matches:</span> {eventScan.usb_connection_count ?? 0}</p>
            <p><span className="text-slate-400">Transfer matches:</span> {eventScan.file_transfer_count ?? 0}</p>
            <p><span className="text-slate-400">Case ID:</span> {logAnalysis.case_id ?? 'n/a'}</p>
          </div>
          {logAnalysis.error ? <p className="mt-3 text-rose-100">{logAnalysis.error}</p> : null}
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

function StagePill({ stage, activeStage, completedStages, failed }) {
  const isActive = stage.id === activeStage
  const isComplete = completedStages.includes(stage.id)
  const isFailed = failed && isActive

  const stateClass = isFailed
    ? 'border-rose-400/40 bg-rose-500/15 text-rose-100'
    : isComplete
      ? 'border-emerald-400/40 bg-emerald-500/15 text-emerald-100'
      : isActive
        ? 'border-cyan-300/50 bg-cyan-300/15 text-cyan-100'
        : 'border-white/10 bg-white/5 text-slate-400'

  return (
    <div className={`rounded-2xl border px-4 py-3 ${stateClass}`}>
      <p className="text-xs uppercase tracking-[0.25em] opacity-75">{stage.label}</p>
      <p className="mt-1 text-sm">{stage.description}</p>
    </div>
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

export default function App() {
  const [form, setForm] = useState(initialForm)
  const [selectedFile, setSelectedFile] = useState(null)
  const [fileNote, setFileNote] = useState('No file selected yet.')
  const [status, setStatus] = useState(null)
  const [targets, setTargets] = useState([])
  const [recovered, setRecovered] = useState([])
  const [pipeline, setPipeline] = useState(null)
  const [activeTab, setActiveTab] = useState('carver')
  const [activeStage, setActiveStage] = useState('idle')
  const [completedStages, setCompletedStages] = useState([])
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

  const stages = [
    { id: 'queued', label: 'Queued', description: 'Pipeline request is prepared and waiting to start.' },
    { id: 'uploading', label: 'Uploading', description: 'The selected image is copied to the backend upload store.' },
    { id: 'hashing', label: 'Hashing', description: 'The source image is hashed to confirm evidence integrity.' },
    { id: 'carving', label: 'Carving', description: 'The carver scans the image and writes extracted files.' },
    { id: 'orchestrating', label: 'Orchestrating', description: 'Recovered files are hashed, matched, and synced.' },
    { id: 'complete', label: 'Complete', description: 'Results are ready and the dashboard refreshes.' },
  ]

  const tabClasses = (tabName) =>
    `rounded-2xl px-5 py-3 text-sm font-semibold transition ${activeTab === tabName ? 'bg-cyan-400 text-slate-950' : 'bg-white/5 text-slate-300 hover:bg-white/10'}`

  const logStage = (message) => {
    setRunLog((current) => [...current, { time: new Date().toLocaleTimeString(), message }])
  }

  const startRunnerView = () => {
    setActiveTab('runner')
    setActiveStage('queued')
    setCompletedStages([])
    setRunLog([])
  }

  const advanceStage = async (nextStage, message) => {
    setActiveStage(nextStage)
    if (message) {
      logStage(message)
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
    setCompletedStages((current) => (current.includes(nextStage) ? current : [...current, nextStage]))
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
    startRunnerView()

    try {
      await advanceStage('uploading', selectedFile ? 'Uploading selected evidence file to Flask.' : 'Using the local image path directly.')
      await advanceStage('hashing', 'The source image hash is being calculated.')
      await advanceStage('carving', 'The carver is scanning the image for recoverable content.')
      await advanceStage('orchestrating', 'The orchestrator is comparing carved files to target hashes.')

      const result = selectedFile
        ? await runPipelineByUpload({ caseId: form.case_id, file: selectedFile })
        : await runPipelineByPath({ caseId: form.case_id, imagePath: form.image_path })

      setPipeline(result)
      setCompletedStages((current) => [...new Set([...current, 'uploading', 'hashing', 'carving', 'orchestrating', 'complete'])])
      setActiveStage('complete')
      logStage('Pipeline finished and the dashboard data was refreshed.')
      if (result.ok) {
        await loadDashboard()
      }
    } catch (error) {
      setPipeline({ ok: false, error: error.message })
      setActiveStage('carving')
      logStage(`Pipeline failed: ${error.message}`)
    } finally {
      setRunning(false)
    }
  }

  const runRamAction = async (runner, successMessage) => {
    // Prevent duplicate submissions while a request is in-flight.
    if (ramBusyRef.current) return
    ramBusyRef.current = true
    setRamRunning(true)
    try {
      const result = ramSelectedFile
        ? await runner({ caseId: form.case_id, file: ramSelectedFile })
        : await runner({ caseId: form.case_id, imagePath: ramImagePath })

      // If the API returned a stored_path (from an upload), update the
      // RAM image path field so the text input reflects the actual file on disk.
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
    // When a file is selected for upload, clear the stale path so it's
    // obvious the upload widget is in control (not the text field).
    if (file) {
      setRamImagePath('')
    }
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.18),_transparent_42%),linear-gradient(180deg,#020617_0%,#07111f_48%,#020617_100%)] text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-8 px-6 py-8 lg:px-10">
        <header className="overflow-hidden rounded-[2rem] border border-white/10 bg-white/5 p-8 shadow-[0_30px_100px_rgba(0,0,0,0.35)] backdrop-blur">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.45em] text-cyan-200/80">SwiftProbe</p>
              <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white lg:text-5xl">Evidence pipeline dashboard</h1>
              <p className="mt-4 max-w-3xl text-base leading-7 text-slate-300">
                Trigger the forensic pipeline, review target hashes, and inspect recovered files from a single app surface.
              </p>
            </div>
            <div className="rounded-2xl border border-cyan-300/20 bg-cyan-300/10 px-4 py-3 text-sm text-cyan-100">
              {loading
                ? 'Refreshing dashboard…'
                : status?.backend_unreachable
                  ? 'Backend unavailable'
                  : statusText}
            </div>
          </div>
        </header>

        <section className="flex flex-wrap gap-3 rounded-3xl border border-white/10 bg-slate-950/70 p-3 shadow-2xl">
          <button
            type="button"
            onClick={() => setActiveTab('carver')}
            className={tabClasses('carver')}
          >
            File Carver and Orchestration
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('ram')}
            className={tabClasses('ram')}
          >
            RAM Module
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('log')}
            className={tabClasses('log')}
          >
            Log Module
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
              <form onSubmit={runPipeline} className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h2 className="text-2xl font-semibold text-white">Run evidence pipeline</h2>
                    <p className="mt-2 text-sm text-slate-400">
                      Upload a raw image or use a local path, then hash the file, carve recoverable content, compare against target hashes, and persist recovered rows.
                    </p>
                  </div>
                  <button
                    type="submit"
                    disabled={running}
                    className="rounded-full bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {running ? 'Running…' : 'Run Pipeline'}
                  </button>
                </div>

                <div className="mt-6 grid gap-4 md:grid-cols-2">
                  <label className="flex flex-col gap-2 text-sm text-slate-300">
                    Image path
                    <input
                      value={form.image_path}
                      onChange={(event) => setForm((current) => ({ ...current, image_path: event.target.value }))}
                      className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/50"
                    />
                  </label>
                  <label className="flex flex-col gap-2 text-sm text-slate-300">
                    Case ID
                    <input
                      value={form.case_id}
                      onChange={(event) => setForm((current) => ({ ...current, case_id: event.target.value }))}
                      className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/50"
                    />
                  </label>
                </div>

                <label className="mt-4 flex cursor-pointer flex-col gap-3 rounded-[1.5rem] border border-dashed border-cyan-300/30 bg-cyan-300/5 p-5 text-sm text-slate-300 transition hover:border-cyan-300/60 hover:bg-cyan-300/10">
                  <span className="text-xs uppercase tracking-[0.3em] text-cyan-200/80">Evidence file upload</span>
                  <span className="text-base text-white">Choose a raw image from your device</span>
                  <span className="text-slate-400">{fileNote}</span>
                  <input type="file" className="hidden" onChange={handleFileChange} accept=".dd,.raw,.img,.bin,.e01,.evtx" />
                </label>

                <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-slate-300">
                  <p className="font-medium text-white">Execution mode</p>
                  <p className="mt-2">
                    {selectedFile
                      ? 'The selected file will be uploaded to Flask and processed visually in the dashboard.'
                      : 'No upload selected, so the pipeline will use the image path field.'}
                  </p>
                </div>

                {pipeline ? (
                  <div className={`mt-6 rounded-2xl border p-4 ${pipeline.ok ? 'border-emerald-400/20 bg-emerald-500/10' : 'border-rose-400/20 bg-rose-500/10'}`}>
                    <p className="text-sm uppercase tracking-[0.35em] text-slate-300">Latest pipeline result</p>
                    <div className="mt-3 grid gap-3 md:grid-cols-3">
                      <div>
                        <p className="text-xs text-slate-400">Total carved</p>
                        <p className="text-2xl font-semibold text-white">{pipeline.total_files_carved ?? 0}</p>
                      </div>
                      <div>
                        <p className="text-xs text-slate-400">Matches found</p>
                        <p className="text-2xl font-semibold text-white">{pipeline.total_matches_found ?? 0}</p>
                      </div>
                      <div>
                        <p className="text-xs text-slate-400">Sync status</p>
                        <p className="text-2xl font-semibold text-white">{pipeline.database_sync_status ?? 'unknown'}</p>
                      </div>
                    </div>
                    {pipeline.source_image_hash ? (
                      <div className="mt-4 grid gap-2 rounded-2xl border border-white/10 bg-slate-950/40 p-4 text-sm text-slate-200">
                        <p><span className="text-slate-400">Source hash:</span> {pipeline.source_image_hash}</p>
                        <p><span className="text-slate-400">Source size:</span> {Number(pipeline.source_image_size ?? 0).toLocaleString()} bytes</p>
                        {pipeline.stored_path ? <p><span className="text-slate-400">Saved upload:</span> {pipeline.stored_path}</p> : null}
                      </div>
                    ) : null}
                    {pipeline.error ? <p className="mt-4 text-sm text-rose-100">{pipeline.error}</p> : null}
                  </div>
                ) : null}
              </form>

              <section className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6 shadow-2xl">
                <h2 className="text-2xl font-semibold text-white">Operational guidance</h2>
                <div className="mt-4 space-y-4 text-sm leading-7 text-slate-300">
                  <p>1. Load target hashes into Supabase using the schema from <span className="text-cyan-200">sql.md</span>.</p>
                  <p>2. Keep raw evidence in the ignored evidence folders and run the pipeline against a local image copy.</p>
                  <p>3. Use this dashboard to confirm the source hash, inspect matches, and review recovered file rows by case ID.</p>
                  <p>4. When the Flask app is running on port 5000, this frontend uses the Vite proxy to read the API.</p>
                </div>
                <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-slate-300">
                  <p className="font-medium text-white">Current status</p>
                  <p className="mt-2">
                    {status?.backend_unreachable
                      ? `Backend unavailable: ${status.error}`
                      : status?.status
                        ? `Backend status: ${status.status}`
                        : 'Waiting for backend status'}
                  </p>
                  <p className="mt-1">{status?.target_artifacts_count ?? 0} target hashes available</p>
                  <p className="mt-1">{status?.files_recovered_count ?? 0} recovered rows available</p>
                </div>
              </section>
            </section>

            <section className="grid gap-6 xl:grid-cols-2">
              <DataTable
                title="Target Artifacts"
                rows={targets}
                emptyText="No target hashes returned. Check Supabase configuration and ensure target_artifacts contains data."
              />
              <DataTable
                title={`Recovered Files${form.case_id ? ` — ${form.case_id}` : ''}`}
                rows={recovered}
                emptyText="No recovered files have been loaded for this case yet."
              />
            </section>
          </>
        ) : activeTab === 'ram' ? (
          <section className="flex flex-col gap-8">
            {/* ── Setup card ── */}
            <div className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl">
              <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">RAM module</p>
              <h2 className="mt-3 text-3xl font-semibold text-white">Volatile memory analysis</h2>
              <p className="mt-4 text-sm leading-7 text-slate-400">
                Run a sanity check first, then analyze a RAM capture for processes, process trees, and network artifacts.
                The module accepts local paths or uploads.
              </p>

              <div className="mt-6 grid gap-4 sm:grid-cols-3">
                <label className="flex flex-col gap-2 text-sm text-slate-300 sm:col-span-2">
                  Case ID
                  <input
                    value={form.case_id}
                    onChange={(event) => setForm((current) => ({ ...current, case_id: event.target.value }))}
                    className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/50"
                  />
                </label>
                <div className="flex items-end justify-end gap-3 sm:col-span-1">
                  <button
                    type="button"
                    onClick={runRamSanityCheck}
                    disabled={ramRunning}
                    className="rounded-full bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {ramRunning ? 'Running…' : 'Sanity Check'}
                  </button>
                  <button
                    type="button"
                    onClick={runRamAnalysis}
                    disabled={ramRunning}
                    className="rounded-full border border-white/10 bg-white/5 px-5 py-3 text-sm font-semibold text-white transition hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {ramRunning ? 'Running…' : 'Analyze'}
                  </button>
                </div>
              </div>
              <label className="mt-4 flex flex-col gap-2 text-sm text-slate-300">
                RAM image path
                <input
                  value={ramImagePath}
                  onChange={(event) => setRamImagePath(event.target.value)}
                  placeholder="Enter a file path or upload a file below"
                  className="w-full overflow-hidden text-ellipsis whitespace-nowrap rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/50"
                />
              </label>

              <label className="mt-6 flex cursor-pointer flex-col gap-3 rounded-[1.5rem] border border-dashed border-cyan-300/30 bg-cyan-300/5 p-5 text-sm text-slate-300 transition hover:border-cyan-300/60 hover:bg-cyan-300/10">
                <span className="text-xs uppercase tracking-[0.3em] text-cyan-200/80">RAM capture upload</span>
                <span className="text-base text-white">Choose a memory image from your device</span>
                <span className="text-slate-400">{ramFileNote}</span>
                <input
                  type="file"
                  className="hidden"
                  onChange={handleRamFileChange}
                  accept=".raw,.mem,.dmp,.vmem,.lime,.aff4,.mddramimage"
                />
              </label>
            </div>

            {/* ── Sanity results ── */}
            <RamSanitySection sanityReport={ramSanity?.report ?? ramSanity} />

            {/* ── Analysis results ── */}
            <RamAnalysisSection analysisReport={ramAnalysis} />
          </section>
        ) : (
          <section className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
            <div className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">Log module</p>
                  <h2 className="mt-2 text-3xl font-semibold text-white">File metadata and device activity</h2>
                  <p className="mt-2 text-sm text-slate-400">
                    This tab reflects the current upload analysis: file metadata, EVTX parsing, USB connection detection, and file-transfer hints.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setActiveTab('carver')}
                  className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-200 transition hover:bg-white/10"
                >
                  Open File Carver
                </button>
              </div>

              <div className="mt-6 grid gap-3 md:grid-cols-3">
                <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4">
                  <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Metadata</p>
                  <p className="mt-2 text-sm text-slate-200">File hash, timestamps, MIME, and upload details.</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4">
                  <p className="text-xs uppercase tracking-[0.3em] text-slate-400">USB trace</p>
                  <p className="mt-2 text-sm text-slate-200">Event-log search for removable-device connection activity.</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4">
                  <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Transfer trace</p>
                  <p className="mt-2 text-sm text-slate-200">Event-log search for file transfer or copy initialization.</p>
                </div>
              </div>

              <div className="mt-6 space-y-3 text-sm text-slate-300">
                <p>Use the file-carver tab to upload a sample and refresh this analysis payload.</p>
                <p>The backend log module is already connected to the pipeline response, so this view updates from the latest run.</p>
              </div>
            </div>

            <LogIntelligencePanel logAnalysis={logAnalysis} />

            <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-6 shadow-2xl xl:col-span-2">
              <h3 className="text-lg font-semibold text-white">Run log</h3>
              <div className="mt-4 space-y-3">
                {runLog.length ? (
                  runLog.map((entry, index) => (
                    <div key={`${entry.time}-${index}`} className="rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-slate-200">
                      <p className="text-xs uppercase tracking-[0.25em] text-slate-400">{entry.time}</p>
                      <p className="mt-1">{entry.message}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-slate-400">No run events yet. Use the File Carver tab to run the pipeline and populate the log module.</p>
                )}
              </div>
            </section>
          </section>
        )}
      </div>
    </main>
  )
}