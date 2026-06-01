from __future__ import annotations

import os
from pathlib import Path
from typing import List, Dict, Optional

from backend.core.supabase_db import get_supabase_client


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

    return results
