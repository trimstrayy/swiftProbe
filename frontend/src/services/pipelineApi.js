async function parseJson(response) {
  const rawText = await response.text()
  let payload = null

  if (rawText) {
    try {
      payload = JSON.parse(rawText)
    } catch (error) {
      const fallbackMessage = rawText.slice(0, 240) || `Request failed with status ${response.status}`
      throw new Error(fallbackMessage)
    }
  }

  if (!response.ok) {
    const message = payload?.error || rawText || `Request failed with status ${response.status}`
    throw new Error(message)
  }

  return payload ?? {}
}

export async function fetchStatus() {
  const response = await fetch('/api/status')
  return parseJson(response)
}

export async function fetchTargets() {
  const response = await fetch('/api/targets')
  return parseJson(response)
}

export async function fetchRecoveredFiles(caseId) {
  const response = await fetch(`/api/recovered-files?case_id=${encodeURIComponent(caseId)}`)
  return parseJson(response)
}

export async function runPipelineByPath({ caseId, imagePath }) {
  const response = await fetch('/api/pipeline/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ case_id: caseId, image_path: imagePath }),
  })

  return parseJson(response)
}

export async function runPipelineByUpload({ caseId, file }) {
  const formData = new FormData()
  formData.append('case_id', caseId)
  formData.append('image_file', file)

  const response = await fetch('/api/pipeline/upload', {
    method: 'POST',
    body: formData,
  })

  return parseJson(response)
}

export async function runRamSanityByPath({ caseId, imagePath }) {
  const response = await fetch('/api/ram/sanity', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ case_id: caseId, image_path: imagePath }),
  })

  return parseJson(response)
}

export async function runRamAnalysisByPath({ caseId, imagePath }) {
  const response = await fetch('/api/ram/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ case_id: caseId, image_path: imagePath }),
  })

  return parseJson(response)
}

export async function runRamSanityByUpload({ caseId, file }) {
  const formData = new FormData()
  formData.append('case_id', caseId)
  formData.append('ram_file', file)

  const response = await fetch('/api/ram/sanity', {
    method: 'POST',
    body: formData,
  })

  return parseJson(response)
}

export async function runRamAnalysisByUpload({ caseId, file }) {
  const formData = new FormData()
  formData.append('case_id', caseId)
  formData.append('ram_file', file)

  const response = await fetch('/api/ram/analyze', {
    method: 'POST',
    body: formData,
  })

  return parseJson(response)
}