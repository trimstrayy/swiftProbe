"""Orchestration layer for evidence processing.

Provides `process_evidence_pipeline(image_path, case_id)` which runs the
end-to-end pipeline: hash source image, run the carver, hash carved files,
compare against target hashes, and insert telemetry into Supabase `files_recovered`.

This module uses environment variables `SUPABASE_URL` and `SUPABASE_KEY`.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Dict

from backend.hasher import hash_file, normalize_sha256
from backend.core.supabase_db import get_supabase_client


def process_evidence_pipeline(image_path: str, case_id: str) -> List[Dict]:
    """Process an evidence image and record recovered files to Supabase.

    Returns a list of recovered-file payloads that were processed locally.
    """
    image_path = str(image_path)
    if not Path(image_path).exists():
        raise FileNotFoundError(f"Evidence image not found: {image_path}")

    print(f"[orchestrator] Hashing source image: {image_path}")
    img_meta = hash_file(image_path)
    print(f"[orchestrator] Source image SHA256: {img_meta.get('hash')}")

    supa = get_supabase_client()
    target_set = set()
    if supa is not None:
        try:
            resp = supa.table("target_artifacts").select("expected_sha256,filename").execute()
            rows = getattr(resp, "data", []) or []
            for r in rows:
                if r.get("expected_sha256"):
                    target_set.add(normalize_sha256(r["expected_sha256"]))
            print(f"[orchestrator] Loaded {len(target_set)} target fingerprints from Supabase")
        except Exception as exc:
            print("[orchestrator] Failed to fetch target_artifacts:", exc)

    # Run the carver (use existing carve_from_image implementation)
    from modules.carver import carve_from_image

    outdir = Path("evidence") / "carved_output" / case_id
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[orchestrator] Running carver -> {outdir}")
    try:
        carved_meta = carve_from_image(image_path, str(outdir))
    except Exception as exc:
        print("[orchestrator] Carver failed:", exc)
        carved_meta = []

    # Build a path -> metadata mapping for quick lookup
    path_map = {str(Path(m.get("path"))): m for m in carved_meta if m.get("path")}

    processed = []
    # Walk carved outputs and check matches
    for root, _dirs, files in os.walk(outdir):
        for fname in files:
            fpath = Path(root) / fname
            try:
                fmeta = hash_file(str(fpath))
                actual = normalize_sha256(fmeta.get("hash", ""))

                # Attempt to find physical offset/length from carver metadata
                meta_entry = path_map.get(str(fpath)) or {}
                offset = meta_entry.get("offset") if meta_entry else None
                length = meta_entry.get("length") if meta_entry else fmeta.get("size")

                match = actual in target_set
                if match:
                    print(f"[orchestrator] *** POSITIVE MATCH: {fname} sha256={actual}")

                payload = {
                    "case_id": case_id,
                    "filename": fname,
                    "actual_sha256": actual,
                    "physical_offset_bytes": int(offset) if offset is not None else 0,
                    "file_size_bytes": int(length) if length is not None else int(fmeta.get("size", 0)),
                    "match_found": bool(match),
                }

                # Best-effort insert into Supabase
                if supa is not None:
                    try:
                        supa.table("files_recovered").insert(payload).execute()
                    except Exception as exc:
                        print("[orchestrator] Failed to insert files_recovered row:", exc)

                processed.append(payload)
            except Exception as exc:
                print(f"[orchestrator] Failed processing carved file {fpath}:", exc)

    print(f"[orchestrator] Pipeline complete. Processed {len(processed)} carved items.")
    return processed


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Process evidence image and match against target hashes")
    parser.add_argument("image_path")
    parser.add_argument("case_id")
    args = parser.parse_args()
    process_evidence_pipeline(args.image_path, args.case_id)
