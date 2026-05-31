"""Run a forensic workflow that hashes the source image before carving.

Usage:
  python scripts/investigate_image.py <image> <output_dir>
  python scripts/investigate_image.py <image> <output_dir> --target-hash <sha256> --label "stolen-file"
"""

from __future__ import annotations

import argparse
import os
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend import hasher
from modules import carver, disk_module


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash a forensic image, store target hashes, then carve and compare")
    parser.add_argument("image", help="Path to a forensic image (.raw, .dd, .E01, .img)")
    parser.add_argument("output_dir", help="Directory to store carved output")
    parser.add_argument("--target-hash", dest="target_hash", help="Known stolen-file SHA-256 to store in target_artifacts")
    parser.add_argument("--label", default=None, help="Optional label for the target artifact")
    parser.add_argument("--case-id", default=None, help="Optional case identifier")
    args = parser.parse_args()

    image_metadata = disk_module.hash_source_image(args.image)
    print("SOURCE_IMAGE_HASHED:", image_metadata)

    if args.target_hash:
        stored = hasher.store_target_artifact(args.target_hash, label=args.label, case_id=args.case_id)
        print("TARGET_STORED:", stored or {"sha256": hasher.normalize_sha256(args.target_hash)})

    carved = carver.carve_from_image(args.image, args.output_dir)
    print("CARVED_COUNT:", len(carved))
    for item in carved:
        print(item)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
