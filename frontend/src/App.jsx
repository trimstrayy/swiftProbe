import { useEffect, useMemo, useState } from 'react'
import {
  fetchStatus,
  fetchTargets,
  fetchRecoveredFiles,
  runPipelineByPath,
  runPipelineByUpload,
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
      <p className="mt-2 text-sm text-slate-300">{hint}</p>
    </article>
  )
}

function DataTable({ title, rows, emptyText }) {
  return (
    <section className="rounded-3xl border border-white/10 bg-slate-950/70 p-5 shadow-2xl">
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-lg font-semibold text-white">{title}</h2>
        <span className="text-sm text-slate-400">{rows.length} rows</span>
      </div>
      {rows.length ? (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full divide-y divide-white/10 text-left text-sm">
            <thead className="text-slate-300">
              <tr>
                {Object.keys(rows[0]).map((key) => (
                  <th key={key} className="px-3 py-2 font-medium uppercase tracking-[0.2em]">
                    {key}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-100">
              {rows.map((row, index) => (
                <tr key={`${title}-${index}`} className={row.match_found ? 'bg-emerald-500/10' : ''}>
                  {Object.values(row).map((value, cellIndex) => (
                    <td key={`${index}-${cellIndex}`} className="px-3 py-2 align-top text-slate-200">
                      {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value ?? '')}
                    </td>
                  ))}
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
        <div>
          <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">Log intelligence</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">File metadata and device activity</h2>
        </div>
        <div
          className={`rounded-2xl px-4 py-3 text-sm ${analysisFailed ? 'border border-rose-400/30 bg-rose-500/15 text-rose-100' : 'border border-cyan-300/20 bg-cyan-300/10 text-cyan-100'}`}
        >
          {analysisFailed ? 'Log analysis failed' : 'Log analysis ready'}
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
          {analysisFailed ? <p className="mt-3 text-rose-100">{analysisError}</p> : null}
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
                        {pipeline.log_analysis_ok === false ? <p className="text-rose-100">Log analysis failed: {pipeline.log_analysis_error ?? 'Unknown error'}</p> : null}
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
          <section className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-10 shadow-2xl">
            <div className="max-w-3xl">
              <p className="text-xs uppercase tracking-[0.35em] text-cyan-200/80">RAM module</p>
              <h2 className="mt-3 text-3xl font-semibold text-white">Reserved for volatile-memory analysis</h2>
              <p className="mt-4 text-sm leading-7 text-slate-400">
                This section is intentionally blank for now so the RAM module can be added separately without changing the file-carver or log workflows.
              </p>
            </div>
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
