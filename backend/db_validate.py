"""Database validation helpers.

Performs best-effort checks against Supabase to ensure required tables and
columns exist. This is intended as a convenience script for operators; it
does not modify production data.
"""
from __future__ import annotations

from typing import Dict, List

from backend.core.supabase_db import get_supabase_client, get_supabase_config


REQUIRED_SCHEMA = {
    "target_artifacts": ["filename", "expected_sha256", "description"],
    "files_recovered": [
        "case_id",
        "filename",
        "actual_sha256",
        "physical_offset_bytes",
        "file_size_bytes",
        "match_found",
        "source_image_path",
        "source_image_sha256",
        "source_image_size",
        "source_image_mtime",
        "carved_file_path",
        "carved_file_type",
        "carved_metadata_json",
        "source_metadata_json",
    ],
    "file_operations": [
        "case_id",
        "operation_type",
        "source_image_path",
        "source_image_name",
        "source_image_sha256",
        "source_image_size",
        "source_image_mtime",
        "output_dir",
        "carved_file_count",
        "matched_file_count",
        "source_metadata",
        "carved_output",
        "recovered_files",
    ],
}


def _init_client():
    client = get_supabase_client()
    if client is not None:
        return client

    url, key = get_supabase_config()
    if not url or not key:
        raise RuntimeError(
            "Set NEXT_PUBLIC_SUPABASE_URL + NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY, or SUPABASE_URL + SUPABASE_KEY"
        )

    raise RuntimeError("Failed to initialize Supabase client")


def validate_schema() -> Dict[str, Dict[str, object]]:
    client = _init_client()
    results = {}

    for table, cols in REQUIRED_SCHEMA.items():
        table_ok = False
        cols_found: List[str] = []
        try:
            resp = client.table(table).select("*").limit(1).execute()
            rows = getattr(resp, "data", []) or []
            if rows:
                # inspect keys of the first row
                cols_found = list(rows[0].keys())
            else:
                # no rows; attempt a head request for column metadata by selecting 0 rows
                resp0 = client.table(table).select("*").limit(0).execute()
                # some client versions include "columns" metadata; fall back to empty
                cols_found = getattr(resp0, "data", []) or []
                if isinstance(cols_found, list) and len(cols_found) == 0:
                    # we can't determine columns from empty data reliably
                    cols_found = []

            table_ok = True
        except Exception as exc:
            results[table] = {"ok": False, "error": str(exc), "found_columns": []}
            continue

        results[table] = {"ok": table_ok, "found_columns": cols_found, "missing": [c for c in cols if c not in cols_found]}

    return results


if __name__ == "__main__":
    import json

    try:
        res = validate_schema()
        print(json.dumps(res, indent=2))
    except Exception as exc:
        print("Validation failed:", exc)
