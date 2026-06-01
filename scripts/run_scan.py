"""Simple CLI to run the disk scanner locally for testing.

Usage:
    python scripts/run_scan.py /path/to/image.dd
"""
from pathlib import Path
import sys

from backend.modules.disk_module import scan_disk_image


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/run_scan.py <image_path>")
        sys.exit(2)

    image = sys.argv[1]
    out = Path("outputs") / "carved_tests"
    out.mkdir(parents=True, exist_ok=True)

    results = scan_disk_image(image, outdir=str(out))
    print(f"Found {len(results)} carved items")
    for r in results:
        print(r)


if __name__ == "__main__":
    main()
