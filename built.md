**SwiftProbe Built System Summary**

SwiftProbe is being built as a forensic investigation platform for handling disk, memory, and log evidence in a structured pipeline.

**What has been built**

- A Python 3.11 virtual environment for the main backend work.
- Core Python packages for the forensic stack, including Flask, Supabase, python-dotenv, Volatility3, python-evtx, requests, and pydantic.
- A file hashing module at `backend/hasher.py`.
- A file carving module at `modules/carver.py`.
- Phase 1 verification and admin setup scripts under `scripts/`.
- A `.env.template` file for configuring Supabase and Sleuth Kit paths.
- A `task.md` roadmap that breaks development into phases.

**What the built code does**

- `backend/hasher.py` reads a file in 64 KB chunks and computes its SHA-256 hash without loading the full file into memory.
- The hasher returns metadata such as filename, full path, file size, and modified time in UTC.
- The hasher also includes a Supabase upload helper for storing evidence metadata in the `evidence_sources` table when environment variables are configured.
- `modules/carver.py` performs signature-based carving for common file types such as JPG, PNG, PDF, and ZIP.
- The carver scans an image or binary file, extracts matching content, writes carved files to an output folder, and records basic metadata.

**Current setup status**

- The main hashing and carving modules are implemented and import successfully.
- The backend verification scripts are present.
- The project is ready for the next forensic modules and API integration.
- Sleuth Kit and pytsk3 were part of the larger setup plan, but they were still the main environment-dependent items to verify for full disk analysis support.

**How to test the built parts**

- Run the hasher on a real file and confirm it prints a SHA-256 metadata dictionary.
- Import `backend.hasher` and `modules.carver` from the `venv311` Python interpreter to confirm both modules load cleanly.
- Run the carver against a sample disk image or binary test file and confirm it produces carved output files.

**Why this matters**

- The hasher is the foundation for evidence integrity tracking.
- The carver is the first recovery tool for extracting file content from raw images.
- Together, they establish the base for later disk analysis, event log parsing, memory analysis, and report generation.
