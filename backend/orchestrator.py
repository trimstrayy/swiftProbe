"""Orchestration layer for evidence processing.

Provides `process_evidence_pipeline(image_path, case_id)` which runs the
end-to-end pipeline: hash source image, run the carver, hash carved files,
compare against target hashes, and insert telemetry into Supabase tables.

This module uses environment variables `SUPABASE_URL` and `SUPABASE_KEY`.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List

from backend.core.supabase_db import get_supabase_client
from backend.hasher import hash_file, normalize_sha256, store_file_operation

logger = logging.getLogger(__name__)


def _insert_recovered_row(supa, payload: Dict[str, object]) -> None:
    """Best-effort insert of a recovered-file row into Supabase."""
    if supa is None:
        return

    try:
        supa.table("files_recovered").insert(payload).execute()
    except Exception:
        logger.exception("Failed to insert files_recovered row")


def process_evidence_pipeline(image_path: str, case_id: str) -> List[Dict]:
    """Process an evidence image and record recovered files to Supabase.

    Returns a list of recovered-file payloads that were processed locally.
    """
    image_path = str(image_path)
    if not Path(image_path).exists():
        raise FileNotFoundError(f"Evidence image not found: {image_path}")

    logger.info("Hashing source image: %s", image_path)
    source_meta = hash_file(image_path)
    source_hash = normalize_sha256(str(source_meta.get("hash", "")))
    logger.info("Source image SHA256: %s", source_hash)

    supa = get_supabase_client()
    target_set = set()
    if supa is not None:
        try:
            resp = supa.table("target_artifacts").select("expected_sha256,filename").execute()
            rows = getattr(resp, "data", []) or []
            for row in rows:
                expected_hash = row.get("expected_sha256")
                if expected_hash:
                    target_set.add(normalize_sha256(expected_hash))
            logger.info("Loaded %s target fingerprints from Supabase", len(target_set))
        except Exception:
            logger.exception("Failed to fetch target_artifacts")

    from modules.carver import carve_from_image

    outdir = Path("evidence") / "carved_output" / case_id
    outdir.mkdir(parents=True, exist_ok=True)

    logger.info("Running carver -> %s", outdir)
    try:
        carved_meta = carve_from_image(image_path, str(outdir))
    except Exception:
        logger.exception("Carver failed")
        carved_meta = []

    post_carve_meta = hash_file(image_path)
    post_carve_hash = normalize_sha256(str(post_carve_meta.get("hash", "")))
    logger.info("Post-carve source image SHA256: %s", post_carve_hash)

    if source_hash != post_carve_hash:
        contaminated_payload = {
            "case_id": case_id,
            "filename": Path(image_path).name,
            "actual_sha256": post_carve_hash,
            "physical_offset_bytes": 0,
            "file_size_bytes": int(post_carve_meta.get("size", 0)),
            "match_found": False,
            "is_integrity_verified": False,
            "source_image_path": image_path,
            "source_image_sha256": source_meta.get("hash"),
            "source_image_size": int(source_meta.get("size", 0)),
            "source_image_mtime": source_meta.get("mtime"),
            "carved_file_path": image_path,
            "carved_file_type": "source-image",
            "carved_metadata_json": {
                "hash_before": source_meta.get("hash"),
                "hash_after": post_carve_meta.get("hash"),
                "pre_carve_metadata": source_meta,
                "post_carve_metadata": post_carve_meta,
            },
            "source_metadata_json": source_meta,
        }
        _insert_recovered_row(supa, contaminated_payload)
        store_file_operation(
            {
                "case_id": case_id,
                "operation_type": "pipeline_run",
                "source_image_path": image_path,
                "source_image_name": source_meta.get("filename"),
                "source_image_sha256": source_meta.get("hash"),
                "source_image_size": int(source_meta.get("size", 0)),
                "source_image_mtime": source_meta.get("mtime"),
                "output_dir": str(outdir),
                "carved_file_count": len(carved_meta),
                "matched_file_count": 0,
                "source_metadata": source_meta,
                "carved_output": carved_meta,
                "recovered_files": [],
            }
        )
        raise RuntimeError("Evidence Contaminated During Processing")

    path_map = {str(Path(meta.get("path"))): meta for meta in carved_meta if meta.get("path")}

    processed: List[Dict] = []
    for root, _dirs, files in os.walk(outdir):
        for fname in files:
            fpath = Path(root) / fname
            try:
                fmeta = hash_file(str(fpath))
                actual = normalize_sha256(fmeta.get("hash", ""))

                meta_entry = path_map.get(str(fpath)) or {}
                offset = meta_entry.get("offset") if meta_entry else None
                length = meta_entry.get("length") if meta_entry else fmeta.get("size")
                carved_type = meta_entry.get("type") if meta_entry else None

                match = actual in target_set
                if match:
                    logger.info("*** POSITIVE MATCH: %s sha256=%s", fname, actual)

                payload = {
                    "case_id": case_id,
                    "filename": fname,
                    "actual_sha256": actual,
                    "physical_offset_bytes": int(offset) if offset is not None else 0,
                    "file_size_bytes": int(length) if length is not None else int(fmeta.get("size", 0)),
                    "match_found": bool(match),
                    "is_integrity_verified": True,
                    "source_image_path": image_path,
                    "source_image_sha256": source_meta.get("hash"),
                    "source_image_size": int(source_meta.get("size", 0)),
                    "source_image_mtime": source_meta.get("mtime"),
                    "carved_file_path": str(fpath),
                    "carved_file_type": carved_type,
                    "carved_metadata_json": {
                        **fmeta,
                        "offset": int(offset) if offset is not None else 0,
                        "length": int(length) if length is not None else int(fmeta.get("size", 0)),
                        "type": carved_type,
                    },
                    "source_metadata_json": source_meta,
                }

                _insert_recovered_row(supa, payload)
                processed.append(payload)
            except Exception:
                logger.exception("Failed processing carved file %s", fpath)

    operation_payload = {
        "case_id": case_id,
        "operation_type": "pipeline_run",
        "source_image_path": image_path,
        "source_image_name": source_meta.get("filename"),
        "source_image_sha256": source_meta.get("hash"),
        "source_image_size": int(source_meta.get("size", 0)),
        "source_image_mtime": source_meta.get("mtime"),
        "output_dir": str(outdir),
        "carved_file_count": len(carved_meta),
        "matched_file_count": len([row for row in processed if row.get("match_found")]),
        "source_metadata": source_meta,
        "carved_output": carved_meta,
        "recovered_files": processed,
    }

    store_file_operation(operation_payload)

    logger.info("Pipeline complete. Processed %s carved items.", len(processed))
    return processed


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Process evidence image and match against target hashes")
    parser.add_argument("image_path")
    parser.add_argument("case_id")
    args = parser.parse_args()
    process_evidence_pipeline(args.image_path, args.case_id)
