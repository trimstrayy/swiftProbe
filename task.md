# SwiftProbe Task Summary

This note records the implemented evidence workflow, the app-facing API layer, and the correct usage flow for the completed system.

## Requirements Completed

- Source-image hashing is handled through the chunked SHA-256 helper in `backend/hasher.py`.
- Signature-based carving is handled through `modules/carver.py`.
- End-to-end orchestration is handled through `backend/orchestrator.py`.
- Supabase connectivity is already supported through `backend/core/supabase_db.py`.
- Flask endpoints expose status, target artifacts, recovered files, pipeline execution, and log analysis.
- The React dashboard reads the API and shows target hashes, recovered rows, pipeline metrics, and log intelligence.
- The React dashboard also supports file upload so the user can run the pipeline without typing a local path.
- Local pipeline testing remains available in `app_test_ui.py` and `scripts/run_scan.py`.
- Evidence provenance and repository hygiene are documented in `README.md` and the `evidence/` guidance files.

## What Was Changed

- Added the local hash → carve → compare → persist workflow in the orchestrator.
- Fixed target-hash handling so the code uses `expected_sha256`, which matches the database schema.
- Added Flask API routes for `GET /api/status`, `GET /api/targets`, `GET /api/recovered-files`, `POST /api/pipeline/run`, and log-aware upload handling.
- Added a Vite proxy so the frontend can reach the Flask API during development.
- Replaced the starter landing page with a dashboard that can launch the pipeline and render live tables plus log intelligence.
- Kept carved output case-specific under `evidence/carved_output/{case_id}/`.

## How To Use Properly

1. Configure Supabase credentials in the environment using either `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, or `SUPABASE_URL` and `SUPABASE_KEY`.
2. Load target hashes into Supabase using the schema from `sql.md` so `target_artifacts.expected_sha256` has real values.
3. Start the Flask backend from the project root with `python backend/app.py`.
4. Start the frontend with `npm run dev` inside the `frontend/` folder.
5. Use the dashboard to upload a raw image or submit an `image_path` and `case_id`, then review the returned metrics and tables.
6. Use `app_test_ui.py` only for local forensic validation when you want the Streamlit workflow instead of the dashboard.
7. Treat `evidence/` as working storage only and keep raw evidence binaries out of version control.

## Practical Validation Flow

- Confirm the source image exists locally before running any pipeline command.
- Use the dashboard to run the pipeline against the selected image and case ID.
- Check the returned metrics for total files carved, total matches found, and database sync status.
- Review the recovered rows in the dashboard or in Supabase directly if you need to audit the inserts.

## Operational Notes

- The backend API is intentionally best-effort around Supabase failures so local carving still completes.
- The frontend reads through the Flask API instead of calling Supabase directly, which keeps the browser layer simpler.
- Uploaded evidence is saved under `evidence/uploads/{case_id}/` before the pipeline runs.
- The existing lab/admin routing work remains separate from the evidence pipeline and can be layered on top later.