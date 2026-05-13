(#) VERDICT — CONCEPTS

## Understanding — What you're building

SwiftProbe is a forensic toolkit that ingests and analyzes evidence from multiple sources (disk images, live RAM captures, logs, and Supabase-hosted artifacts) and presents correlated results in a real-time React dashboard. The project prioritizes safe evidence handling (immediate hashing), robust artifact extraction (disk carving, memory plugins), temporal correlation (a master timeline ordered by UTC), and modern realtime UX via Supabase subscriptions.

---

## 1. Disk Forensics and File Carving

- Concept: Magic Numbers (file signatures). Deleted files remain on disk as "unallocated" space until overwritten. Many file types begin with unique hex headers (e.g., GIF: `47 49 46 38`).
- What to build: A `disk_module` "Carver" that scans raw sectors of a disk image for known signatures and extracts matching byte ranges into files.
- Why it matters: Recovers deleted or fragmented artifacts that other tools miss.
- Watch: File Carving and Header/Footer Analysis

## 2. Volatile Memory (RAM) Analysis

- Concept: Address spaces and VAD trees. Live RAM contains ephemeral evidence (credentials, browser sessions, malware) that disappears on power-off.
- What to build: A RAM analysis module that integrates Volatility 3 plugins (e.g., `pslist`, `psscan`, `netscan`) to enumerate processes, discover hidden processes, and extract network artifacts.
- Why it matters: Captures the live-state that disk images cannot show.
- Watch: Introduction to Memory Forensics with Volatility

## 3. Data Integrity and Hashing

- Concept: Cryptographic hashing (SHA-256) — a single-bit change invalidates evidence integrity.
- What to build: An ingestion service that computes and stores SHA-256 hashes when evidence is first added, and re-verifies hashes before final reports are produced.
- Why it matters: Ensures evidence admissibility and tamper detection.
- Watch: Hashing in Digital Forensics

## 4. The "Master Timeline" Logic

- Concept: Temporal correlation — unify artifacts from diverse sources into a chronological timeline using UTC timestamps.
- What to build: A Supabase query (or server-side function) that merges artifact tables and sorts by timestamp DESC to produce a master timeline.
- Why it matters: Provides context and causality across events.
- Watch: Building a Forensic Timeline

## 5. Modern Web Architecture (The UI/UX)

- Concept: Real-time state via webhooks and subscriptions. The frontend should react to new artifacts without manual refresh.
- What to build: A React `useArtifact` hook (or equivalent) that subscribes to Supabase realtime updates and pushes new artifacts to the dashboard immediately.
- Why it matters: Immediate visibility for triage and investigation.
- Watch: Supabase Realtime with React

---

## Quick NEXT STEPS (suggested)

- Implement a minimal `disk_module` carver that locates and extracts GIF/JPEG/PNG by signature.
- Add an ingestion pipeline that SHA-256 hashes files on add and stores hash metadata in Supabase.
- Wire a simple React subscription hook to display new artifacts in realtime.

