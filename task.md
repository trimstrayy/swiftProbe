"I need to build the orchestration and automated testing layer for SwiftProbe to fulfill our primary objective: detecting stolen/deleted files by comparing recovered artifacts from unallocated space against a list of known target hashes.

Please implement a new module backend/orchestrator.py and an automated test runner script scripts/test_pipeline.py based on the specifications below:
1. Core Logic for backend/orchestrator.py

    Database Sync: Initialize a Supabase client using the environment variables SUPABASE_URL and SUPABASE_KEY from your .env configuration.

    Target Ingestion: Query the target_artifacts table to pull all expected SHA-256 strings into a fast-lookup Python set.

    Base Validation: Before doing anything else, use backend/hasher.py to calculate the SHA-256 hash of the incoming raw forensic image (e.g., L0_Graphic.dd) to verify base evidence integrity.

    Carving Execution: Trigger the run_carver function from modules/carver.py to process the image and extract file fragments into a dedicated, case-specific directory (evidence/carved_output/{case_id}/).

    Post-Carve Verification: Walk through the temporary folder of carved files. For every single file extracted:

        Calculate its SHA-256 hash using the chunked method in backend/hasher.py.

        Check if its hash exists in your target_artifacts lookup set.

        If a match is found, log a critical alert to the console indicating the physical offset or file name.

        Write a new row into the files_recovered table in Supabase containing case_id, filename, actual_sha256, file_size_bytes, and match_found (boolean).

2. Test Harness Structure in scripts/test_pipeline.py

Create a standalone testing script that sets up a mock environment using our newly downloaded NIST L0 non-fragmented images:

    Have it accept arguments or hardcode paths for a test run (e.g., --image evidence/L0_Graphic.dd --case-id NIST-TEST-01).

    Before running the pipeline, it should check if there is at least one row in the Supabase target_artifacts table. If empty, have it print instructions to insert a valid target hash from the NIST ground truth spreadsheet.

    Execute process_evidence_pipeline from the orchestrator and report completion metrics (e.g., Total Files Carved, Total Matches Found, Database Sync Status).

Please generate clean, modular Python 3.11 code with robust error handling (try-except blocks) so that a corrupted sector in a raw disk image does not crash the entire tracking loop."