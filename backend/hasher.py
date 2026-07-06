import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def hash_file(filepath: str, chunk_size: int = 65536) -> Dict[str, object]:
    """Compute SHA-256 of a file in streaming fashion.

    Returns a dict with: hash, filename, size, mtime (iso8601 UTC)
    """
    h = hashlib.sha256()
    total = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)

    stat = os.stat(filepath)
    metadata = {
        "hash": h.hexdigest(),
        "filename": os.path.basename(filepath),
        "path": os.path.abspath(filepath),
        "size": total,
        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    }
    return metadata


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_sha256(value: str) -> str:
    """Normalize a SHA-256 string for consistent comparisons."""
    return value.strip().lower()


def store_target_artifact(target_hash: str, label: Optional[str] = None, case_id: Optional[str] = None) -> Optional[Dict]:
    """Insert a target hash into Supabase `target_artifacts`.

    The table is expected to hold the investigation's known stolen-file hashes.
    If Supabase settings are missing, this function returns None.
    """
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        return None

    try:
        from supabase import create_client

        client = create_client(url, key)
        payload = {
            "expected_sha256": normalize_sha256(target_hash),
            "filename": label or "target_artifact",
            "description": case_id,
        }
        return client.table("target_artifacts").insert(payload).execute()
    except Exception:
        return None


def upload_to_supabase(metadata: Dict[str, object]) -> Optional[Dict]:
    """Attempt to store metadata into Supabase `evidence_sources` table.

    If Supabase env variables are not present, this becomes a no-op and returns None.
    """
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        return None

    try:
        from supabase import create_client

        client = create_client(url, key)
        resp = client.table("evidence_sources").insert({
            "sha256": metadata["hash"],
            "filename": metadata["filename"],
            "size": metadata["size"],
            "path": metadata.get("path"),
            "mtime": metadata.get("mtime"),
        }).execute()
        return resp
    except Exception:
        return None


def fetch_target_hashes() -> set[str]:
    """Fetch known target hashes from Supabase.

    Returns an empty set when Supabase is not configured or the query fails.
    """
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        return set()

    try:
        from supabase import create_client

        client = create_client(url, key)
        response = client.table("target_artifacts").select("expected_sha256,sha256").execute()
        rows = getattr(response, "data", []) or []
        return {
            normalize_sha256(row["expected_sha256"] or row["sha256"])
            for row in rows
            if row.get("expected_sha256") or row.get("sha256")
        }
    except Exception:
        return set()


def mark_target_match(target_hash: str, carved_hash: str, filename: str, offset: int, source_image: Optional[str] = None) -> Optional[Dict]:
    """Mark a target artifact as matched and record the offset where it was found."""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        return None

    try:
        from supabase import create_client

        client = create_client(url, key)
        return (
            client.table("target_artifacts")
            .update(
                {
                    "match_found": True,
                    "matched_hash": normalize_sha256(carved_hash),
                    "matched_filename": filename,
                    "matched_offset": offset,
                    "matched_image": source_image,
                    "matched_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            .eq("expected_sha256", normalize_sha256(target_hash))
            .execute()
        )
    except Exception:
        return None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Hash a file (SHA-256)")
    parser.add_argument("file")
    parser.add_argument("--store-target", action="store_true", help="Store the resulting hash in target_artifacts instead of evidence_sources")
    parser.add_argument("--label", default=None, help="Optional label for a target artifact")
    parser.add_argument("--case-id", default=None, help="Optional case identifier")
    args = parser.parse_args()
    meta = hash_file(args.file)
    if args.store_target:
        result = store_target_artifact(meta["hash"], label=args.label, case_id=args.case_id)
        print(result or meta)
    else:
        print(meta)
