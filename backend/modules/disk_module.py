from __future__ import annotations

import os
from pathlib import Path
from typing import List, Dict, Optional

from backend.core.supabase_db import get_supabase_client
from backend.hasher import hash_file, store_file_operation


def scan_disk_image(image_path: str, outdir: Optional[str] = None, min_size: int = 512) -> List[Dict]:
    """Scan a forensic image for recoverable files using the project carver.

    - `image_path`: path to the .dd/.raw/.img image
    - `outdir`: directory to write carved files (defaults to `outputs/carved/<image>`)
    - returns: list of metadata dicts produced by the carver
    """
    from modules.carver import carve_from_image

    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    base = Path(image_path).stem
    default_out = Path("outputs") / "carved" / base
    outdir_path = Path(outdir) if outdir else default_out
    outdir_path.mkdir(parents=True, exist_ok=True)

    results = carve_from_image(image_path, str(outdir_path), min_size=min_size)
    source_meta = hash_file(image_path)

    # Optionally upload recovered metadata to Supabase if available
    supa = get_supabase_client()
    if supa is not None and results:
        try:
            payload = [
                {
                    "image_path": r.get("source_image", image_path),
                    "file_path": r.get("path"),
                    "file_type": r.get("type"),
                    "offset": r.get("offset"),
                    "length": r.get("length"),
                    "sha256": r.get("sha256"),
                }
                for r in results
            ]
            # insert rows (best-effort; ignore if table missing)
            supa.table("recovered_files").insert(payload).execute()
        except Exception:
            # non-fatal: keep local results even if upload fails
            pass

        try:
            store_file_operation(
                {
                    "case_id": Path(image_path).stem,
                    "operation_type": "disk_scan",
                    "source_image_path": image_path,
                    "source_image_name": source_meta.get("filename"),
                    "source_image_sha256": source_meta.get("hash"),
                    "source_image_size": int(source_meta.get("size", 0)),
                    "source_image_mtime": source_meta.get("mtime"),
                    "output_dir": str(outdir_path),
                    "carved_file_count": len(results),
                    "matched_file_count": len([row for row in results if row.get("match_found")]),
                    "source_metadata": source_meta,
                    "carved_output": results,
                    "recovered_files": results,
                }
            )
        except Exception:
            pass

    return results
