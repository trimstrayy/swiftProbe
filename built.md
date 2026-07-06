**SwiftProbe Built System Summary**

SwiftProbe now has a working evidence pipeline and an app-facing data layer: chunked hashing, signature-based carving, Supabase connectivity, local orchestration, Flask API routes, a React dashboard with file-upload support, and a log module that extracts file metadata and scans device event logs for USB/file-transfer activity. The repo also documents evidence provenance and keeps bundled sample data out of version control.

**What has already been built**

- Repository hygiene for evidence data is in place, including ignore rules for raw images and extracted samples.
- The bundled evidence provenance is documented in `README.md` and the `evidence/` guidance files.
- `backend/hasher.py` computes SHA-256 hashes in chunks and returns evidence metadata.
- `modules/carver.py` scans raw images for JPG, PNG, PDF, and ZIP signatures and writes carved output files.
- `backend/modules/disk_module.py` wraps the carver for disk-image scanning and optional Supabase uploads.
- `backend/modules/log_module.py` extracts file metadata and analyzes EVTX/device activity.
- `backend/core/supabase_db.py` accepts both backend-style and `NEXT_PUBLIC_` Supabase environment variables.
- `backend/orchestrator.py` runs the hash → carve → compare → persist flow and writes recovered-file records to Supabase when configured.
- `backend/app.py` exposes status, target artifact, recovered-file, and pipeline-run endpoints.
- `app_test_ui.py` provides a Streamlit test UI for hashing, carving, orchestration, and recovered-file review.
- `frontend/src/App.jsx` provides the browser dashboard for pipeline execution, file upload, and data review.
- `frontend/src/services/pipelineApi.js` centralizes the React-to-Flask API calls.
- `backend/db_validate.py` performs best-effort Supabase schema validation.
- `scripts/run_scan.py` gives a local CLI entrypoint for carving tests.
- `sql.md`, `task.md`, and `concept.md` capture the schema bootstrap, roadmap, and forensic workflow notes.

**Current setup status**

- The hashing, carving, orchestration, API, and dashboard paths are implemented and import successfully.
- The project is now ready for interactive evidence runs through the browser dashboard.
- Sleuth Kit and `pytsk3` remain the main environment-dependent pieces to verify for deeper disk analysis.

**Why this matters**

- The hasher establishes evidence integrity.
- The carver recovers content from raw images.
- The orchestrator ties those steps to target matching and database persistence.
- The remaining work is now about broadening the forensic scope and tightening the role-based app workflow.
