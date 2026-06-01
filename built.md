**SwiftProbe Built System Summary**

SwiftProbe is a forensic investigation platform for handling disk, memory, and log evidence in a structured pipeline. The latest update cleaned accidental evidence binaries out of git history, locked the evidence folder down in `.gitignore`, and documented the provenance of the bundled sample datasets.

**Latest update**

- Removed the committed evidence images from repository history and force-pushed the cleaned `main` branch.
- Added ignore rules for `evidence/` binaries and evidence subfolders so future sample data stays out of version control.
- Added a provenance note to the main README pointing to the NIST CFReDS File Carving archive.
- Kept the evidence guidance files in `evidence/` so the repo still explains where to place local datasets and how to validate them.

**What is in the repo now**

- A Python virtual environment for backend work.
- Core Python packages for the forensic stack, including Flask, Supabase, python-dotenv, Volatility 3, python-evtx, requests, and pydantic.
- A file hashing module at `backend/hasher.py`.
- A file carving module at `modules/carver.py`.
- A disk scanning wrapper at `backend/modules/disk_module.py` that calls the carver and optionally uploads recovered metadata to Supabase.
- A log parsing scaffold at `backend/modules/log_module.py` to parse EVTX files when `python-evtx` is available.
- A simple CLI test runner at `scripts/run_scan.py` to exercise image carving locally.
- An orchestration entrypoint at `backend/orchestrator.py` providing `process_evidence_pipeline(image_path, case_id)` to run the full ingest → carve → match → persist flow.
- A Streamlit test UI `app_test_ui.py` to run the pipeline from a browser and view targets and recovered files.
- A best-effort DB validation helper at `backend/db_validate.py` to check required Supabase tables and expected columns.
- Supabase connection helpers now accept both `NEXT_PUBLIC_SUPABASE_URL` / `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` and the older backend env names.
- A new `sql.md` file with the complete bootstrap SQL for `target_artifacts` and `files_recovered`.
- The Streamlit test UI now has dedicated Hashing, File Carving, and Orchestration sections plus device file import for raw forensic images.
- Phase 1 verification and admin setup scripts under `scripts/`.
- A `.env.template` file for configuring Supabase and Sleuth Kit paths.
- Roadmap and concept documents in `task.md`, `concept.md`, and `README.md`.
- Evidence guidance documents in `evidence/DATASETS.md` and `evidence/digitalcorpora/README.md`.

**What the built code does now**

- `backend/hasher.py` reads files in 64 KB chunks and computes SHA-256 hashes without loading whole files into memory.
- The hasher returns metadata such as filename, full path, file size, and modified time in UTC.
- The hasher includes a Supabase upload helper for storing evidence metadata in the `evidence_sources` table when environment variables are configured.
- `modules/carver.py` performs signature-based carving for common file types such as JPG, PNG, PDF, and ZIP.
- The carver scans an image or binary file, extracts matching content, writes carved files to an output folder, and records basic metadata.
- The docs now explicitly tell users where the pre-existing evidence came from and how to keep new raw evidence outside git.

**Current setup status**

- The hashing and carving modules are implemented and import successfully.
- The backend verification scripts are present.
- The project is ready for the next forensic modules and API integration.
- Sleuth Kit and pytsk3 remain the primary environment-dependent items to verify for full disk analysis support.

**How to test the built parts**

- Run the hasher on a real file and confirm it prints a SHA-256 metadata dictionary.
- Import `backend.hasher` and `modules.carver` from the active Python interpreter to confirm both modules load cleanly.
- Run the carver against a sample disk image or binary test file and confirm it produces carved output files.

**Why this matters**

- The hasher is the foundation for evidence integrity tracking.
- The carver is the first recovery tool for extracting file content from raw images.
- Together, they establish the base for later disk analysis, event log parsing, memory analysis, and report generation.
