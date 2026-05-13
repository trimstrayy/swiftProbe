import os
from typing import List, Dict, Tuple

from pathlib import Path

CHUNK = 1024 * 1024

SIGNATURES = {
    "jpg": {"header": b"\xff\xd8", "footer": b"\xff\xd9"},
    "png": {"header": b"\x89PNG\r\n\x1a\n", "footer": b"IEND"},
    "pdf": {"header": b"%PDF", "footer": b"%%EOF"},
    "zip": {"header": b"PK\x03\x04", "footer": b"PK\x05\x06"},
}


def _ensure_outdir(outdir: str):
    Path(outdir).mkdir(parents=True, exist_ok=True)


def _write_carved(outdir: str, base_name: str, offset: int, data: bytes) -> str:
    filename = f"{base_name}_{offset:X}.carved"
    path = os.path.join(outdir, filename)
    with open(path, "wb") as o:
        o.write(data)
    return path


def carve_from_image(image_path: str, output_dir: str, min_size: int = 512, max_size: int = 50 * 1024 * 1024) -> List[Dict]:
    """Scan `image_path` for known file signatures and extract carved files.

    Produces carved files in `output_dir` and returns list of metadata dicts
    with keys: path, offset, length, type, sha256 (if hasher available)
    """
    import backend.hasher as hasher

    _ensure_outdir(output_dir)
    results: List[Dict] = []

    with open(image_path, "rb") as f:
        buf = b""
        base_name = os.path.splitext(os.path.basename(image_path))[0]
        offset = 0
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf += chunk

            # scan for headers in buffer
            for fmt, sig in SIGNATURES.items():
                h = sig["header"]
                start = 0
                while True:
                    idx = buf.find(h, start)
                    if idx == -1:
                        break
                    abs_offset = offset + idx

                    # attempt to find footer within max_size
                    footer = sig["footer"]
                    # for PNG IEND is ASCII; we search bytes
                    search_start = idx + len(h)
                    # build a search window from current buffer plus further reads if needed
                    data = buf[idx:]
                    # if footer not in data, try to read more up to max_size
                    while footer not in data and len(data) < max_size:
                        more = f.read(CHUNK)
                        if not more:
                            break
                        data += more
                    # find footer
                    if footer in data:
                        end_idx = data.find(footer) + len(footer)
                        # heuristics: include a few extra bytes for ZIP/PDF
                        if fmt == "png":
                            # include IEND plus 8 bytes (CRC)
                            end_idx += 8
                        elif fmt == "zip":
                            # include 22 bytes to try to capture central directory end
                            end_idx += 22
                        carved = data[:end_idx]
                    else:
                        carved = data[: max_size ]

                    if len(carved) >= min_size:
                        outpath = _write_carved(output_dir, base_name + f".{fmt}", abs_offset, carved)
                        meta = {
                            "path": outpath,
                            "offset": abs_offset,
                            "length": len(carved),
                            "type": fmt,
                        }
                        try:
                            hmeta = hasher.hash_file(outpath)
                            meta["sha256"] = hmeta.get("hash")
                        except Exception:
                            meta["sha256"] = None
                        results.append(meta)

                    # advance start to continue scanning after this header
                    start = idx + 1

            # keep last len(max header) bytes to catch split signatures
            max_header = max(len(s["header"]) for s in SIGNATURES.values())
            if len(buf) > max_header:
                # advance file offset by amount consumed
                consume = len(buf) - max_header
                offset += consume
                buf = buf[-max_header:]

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple signature-based file carver")
    parser.add_argument("image")
    parser.add_argument("outdir")
    args = parser.parse_args()
    found = carve_from_image(args.image, args.outdir)
    for f in found:
        print(f)
