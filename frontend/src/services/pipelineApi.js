import { supabase } from './supabaseClient'

// ── Auth token helpers ───────────────────────────────────────────────────

/**
 * Get the current Supabase session's access token.
 * Returns null if no session exists or the token is missing.
 */
async function getAccessToken() {
  try {
    const { data: { session }, error } = await supabase.auth.getSession()
    if (error) {
      console.warn('[SwiftProbe] Failed to get Supabase session:', error.message)
      return null
    }
    if (!session?.access_token) {
      console.warn('[SwiftProbe] No access token in session — user may not be signed in')
      return null
    }
    return session.access_token
  } catch (err) {
    console.warn('[SwiftProbe] Error getting session:', err.message)
    return null
  }
}

/**
 * Build headers with Authorization for JSON requests.
 * If no token is available, returns headers without Authorization
 * (the backend will return 401 and the caller can handle it).
 */
async function getAuthHeaders() {
  const headers = { 'Content-Type': 'application/json' }
  const token = await getAccessToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return headers
}

/**
 * Build headers with Authorization for multipart/form-data requests.
 * Does NOT set Content-Type — the browser sets it with the correct boundary.
 */
async function getAuthFormDataHeaders() {
  const headers = {}
  const token = await getAccessToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return headers
}

// ── Response parsing & error handling ────────────────────────────────────

/**
 * Parse a JSON response and throw a descriptive error if the request failed.
 * Handles 401 responses by throwing an error with a clear message about
 * authentication.
 */
async function parseJson(response) {
  const rawText = await response.text()
  let payload = null

  if (rawText) {
    try {
      payload = JSON.parse(rawText)
    } catch {
      const fallbackMessage = rawText.slice(0, 240) || `Request failed with status ${response.status}`
      throw new Error(fallbackMessage)
    }
  }

  if (!response.ok) {
    // ── 401 Unauthorized ──────────────────────────────────────────────
    if (response.status === 401) {
      const msg = payload?.error || 'unauthorized'
      console.error('[SwiftProbe] 401 Unauthorized — token may be expired or invalid. Sign in again.')
      throw new Error(`Authentication required (${msg}). Please sign in again.`)
    }

    // ── Other errors ──────────────────────────────────────────────────
    const message = payload?.error || rawText || `Request failed with status ${response.status}`
    throw new Error(message)
  }

  return payload ?? {}
}

// ── API functions ────────────────────────────────────────────────────────

export async function fetchStatus() {
  const response = await fetch('/api/status')
  return parseJson(response)
}

export async function fetchTargets() {
  const headers = await getAuthHeaders()
  const response = await fetch('/api/targets', { headers })
  return parseJson(response)
}

export async function fetchRecoveredFiles(caseId) {
  const headers = await getAuthHeaders()
  const response = await fetch(`/api/recovered-files?case_id=${encodeURIComponent(caseId)}`, { headers })
  return parseJson(response)
}

export async function runPipelineByPath({ caseId, imagePath }) {
  const headers = await getAuthHeaders()
  const response = await fetch('/api/pipeline/run', {
    method: 'POST',
    headers,
    body: JSON.stringify({ case_id: caseId, image_path: imagePath }),
  })
  return parseJson(response)
}

export async function runPipelineByUpload({ caseId, file }) {
  const formData = new FormData()
  formData.append('case_id', caseId)
  formData.append('image_file', file)
  const authHeaders = await getAuthFormDataHeaders()
  const response = await fetch('/api/pipeline/upload', {
    method: 'POST',
    headers: authHeaders,
    body: formData,
  })
  return parseJson(response)
}

export async function runRamSanityByPath({ caseId, imagePath }) {
  const headers = await getAuthHeaders()
  const response = await fetch('/api/ram/sanity', {
    method: 'POST',
    headers,
    body: JSON.stringify({ case_id: caseId, image_path: imagePath }),
  })
  return parseJson(response)
}

export async function runRamAnalysisByPath({ caseId, imagePath }) {
  const headers = await getAuthHeaders()
  const response = await fetch('/api/ram/analyze', {
    method: 'POST',
    headers,
    body: JSON.stringify({ case_id: caseId, image_path: imagePath }),
  })
  return parseJson(response)
}

export async function runRamSanityByUpload({ caseId, file }) {
  const formData = new FormData()
  formData.append('case_id', caseId)
  formData.append('ram_file', file)
  const authHeaders = await getAuthFormDataHeaders()
  const response = await fetch('/api/ram/sanity', {
    method: 'POST',
    headers: authHeaders,
    body: formData,
  })
  return parseJson(response)
}

export async function runRamAnalysisByUpload({ caseId, file }) {
  const formData = new FormData()
  formData.append('case_id', caseId)
  formData.append('ram_file', file)
  const authHeaders = await getAuthFormDataHeaders()
  const response = await fetch('/api/ram/analyze', {
    method: 'POST',
    headers: authHeaders,
    body: formData,
  })
  return parseJson(response)
}

// ── Report Generator API ─────────────────────────────────────────────────

export async function generateReport(caseMeta) {
  const headers = await getAuthHeaders()
  const response = await fetch('/api/report/generate-download', {
    method: 'POST',
    headers,
    body: JSON.stringify({ case_meta: caseMeta }),
  })

  if (!response.ok) {
    if (response.status === 401) {
      console.error('[SwiftProbe] 401 Unauthorized on report generation — token may be expired.')
      throw new Error('Authentication required. Please sign in again.')
    }
    const errorData = await parseJson(response).catch(() => ({}))
    throw new Error(errorData.error || `Report generation failed with status ${response.status}`)
  }

  // Return the PDF blob for download
  const blob = await response.blob()
  const disposition = response.headers.get('Content-Disposition') || ''
  const match = disposition.match(/filename="?(.+?)"?$/)
  const filename = match ? match[1] : `SwiftProbe_Report_${caseMeta.case_number || 'unknown'}.pdf`

  return { blob, filename }
}

export async function downloadReport(caseMeta) {
  const { blob, filename } = await generateReport(caseMeta)

  // Trigger browser download
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)

  return { ok: true, filename }
}

// ── Auth API ─────────────────────────────────────────────────────────────

export async function signInWithPassword(email, password) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password })
  if (error) throw error
  return data
}

export async function signUpWithEmail(email, password) {
  const { data, error } = await supabase.auth.signUp({ email, password })
  if (error) throw error
  return data
}

export async function signInWithMagicLink(email) {
  const { data, error } = await supabase.auth.signInWithOtp({ email })
  if (error) throw error
  return data
}

export async function signOut() {
  const { error } = await supabase.auth.signOut()
  if (error) throw error
}

export async function getCurrentSession() {
  const { data: { session } } = await supabase.auth.getSession()
  return session
}

export async function onAuthStateChange(callback) {
  return supabase.auth.onAuthStateChange((event, session) => {
    callback(event, session)
  })
}