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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Hash a file (SHA-256)")
    parser.add_argument("file")
    args = parser.parse_args()
    meta = hash_file(args.file)
    print(meta)
