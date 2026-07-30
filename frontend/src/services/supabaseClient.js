import { createClient } from '@supabase/supabase-js'

// ── Vite environment variables ───────────────────────────────────────────
// Vite exposes env vars prefixed with VITE_ via import.meta.env.
// Create a `.env` file in the `frontend/` directory with:
//   VITE_SUPABASE_URL=https://your-project.supabase.co
//   VITE_SUPABASE_ANON_KEY=your-anon-key-here
//
// Runtime validation: if either variable is missing or still set to a
// placeholder value, a console.error is emitted so the developer knows
// exactly why Supabase auth calls are failing with "Invalid API key".

const supabaseUrl =
  import.meta.env.VITE_SUPABASE_URL ||
  import.meta.env.VITE_PUBLIC_SUPABASE_URL ||
  ''

const supabaseAnonKey =
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
  ''

// ── Runtime validation ───────────────────────────────────────────────────
const PLACEHOLDER_VALUES = new Set([
  '',
  'your-anon-key-here',
  'your-publishable-key',
  'placeholder-anon-key',
  'YOUR_ANON_KEY',
  'YOUR_SUPABASE_URL',
  'https://placeholder.supabase.co',
  'https://your-project.supabase.co',
])

function isPlaceholder(value) {
  return PLACEHOLDER_VALUES.has(value) || value.trim() === ''
}

if (isPlaceholder(supabaseUrl)) {
  console.error(
    '[SwiftProbe] VITE_SUPABASE_URL is not set or is a placeholder.\n' +
    'Create frontend/.env with:\n' +
    '  VITE_SUPABASE_URL=https://your-project.supabase.co\n' +
    'Found value: "' + supabaseUrl + '"'
  )
}

if (isPlaceholder(supabaseAnonKey)) {
  console.error(
    '[SwiftProbe] VITE_SUPABASE_ANON_KEY is not set or is a placeholder.\n' +
    'Create frontend/.env with:\n' +
    '  VITE_SUPABASE_ANON_KEY=your-anon-key-here\n' +
    'Found value: "' + supabaseAnonKey + '"'
  )
}

if (!supabaseUrl.startsWith('https://') || !supabaseUrl.includes('.supabase.co')) {
  console.warn(
    '[SwiftProbe] VITE_SUPABASE_URL does not look like a valid Supabase URL.\n' +
    'Expected format: https://<project-ref>.supabase.co\n' +
    'Found value: "' + supabaseUrl + '"'
  )
}

if (supabaseAnonKey.length < 20) {
  console.warn(
    '[SwiftProbe] VITE_SUPABASE_ANON_KEY looks too short to be a valid Supabase key.\n' +
    'Expected: a long JWT-style string (starts with "eyJ..." or "sb_publishable_...").\n' +
    'Found value length: ' + supabaseAnonKey.length + ' characters'
  )
}

// Create the client even with placeholder values so the app doesn't
// crash at import time — the console errors above will guide the
// developer to fix their .env file.
export const supabase = createClient(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseAnonKey || 'placeholder-anon-key'
)