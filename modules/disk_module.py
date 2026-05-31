"""Disk-image helpers for SwiftProbe.

This module keeps forensic image handling separate from carving logic so the
pipeline can hash the source image first, then carve recovered files in a
streaming-safe way.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from backend.hasher import hash_file


SUPPORTED_IMAGE_EXTENSIONS = (".raw", ".dd", ".e01", ".img", ".bin")


def is_forensic_image(path: str) -> bool:
    return os.path.isfile(path) and path.lower().endswith(SUPPORTED_IMAGE_EXTENSIONS)


def hash_source_image(image_path: str):
    """Hash the evidence image before any carving begins."""
    if not is_forensic_image(image_path):
        raise ValueError("Expected a forensic image path such as .raw, .dd, .E01, or .img")
    return hash_file(image_path)


@contextmanager
def open_image_stream(image_path: str) -> Iterator[object]:
    """Open an evidence image as a byte stream.

    Raw/dd/img/bin images are opened directly.
    E01 images use pyewf when available.
    """
    if not is_forensic_image(image_path):
        raise ValueError("Expected a forensic image file path, not a directory")

    if image_path.lower().endswith(".e01"):
        try:
            import pyewf

            handle = pyewf.handle()
            handle.open([image_path])
            try:
                yield handle
            finally:
                handle.close()
            return
        except Exception as exc:
            raise RuntimeError("E01 support requires pyewf to be installed") from exc

    with open(image_path, "rb") as stream:
        yield stream
