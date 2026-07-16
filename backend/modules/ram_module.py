"""Volatile memory analysis helpers for SwiftProbe.

This module wraps Volatility 3 plugins in a small, testable API so RAM dumps
can be analyzed for processes, process trees, and active network connections
without coupling the rest of the backend to Volatility internals.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence


SUPPORTED_RAM_EXTENSIONS = (".raw", ".mem", ".dmp", ".vmem", ".lime", ".aff4", ".mddramimage")
MIN_RAM_CAPTURE_SIZE_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 600
VOLATILITY_DRIVER_SNIPPET = "import sys; from volatility3.cli import main; sys.argv = ['volatility3'] + sys.argv[1:]; main()"


class RAMModule:
    """Analyze a volatile memory image with Volatility 3.

    The module currently focuses on the core triage artifacts the rest of the
    project expects: running process enumeration and active network discovery.
    """

    def __init__(self, image_path: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS):
        self.image_path = str(image_path)
        self.timeout_seconds = timeout_seconds

    def is_supported_image(self) -> bool:
        return Path(self.image_path).is_file() and self.image_path.lower().endswith(SUPPORTED_RAM_EXTENSIONS)

    def analyze(self) -> Dict[str, Any]:
        """Run the core memory triage plugins and return a structured summary."""
        validation = self._validate_image_path()
        if validation is not None:
            return validation

        warnings: List[str] = []
        network_backend = None

        process_list = []
        try:
            process_list = self.list_processes()
        except Exception as exc:
            warnings.append(f"pslist unavailable: {exc}")

        process_tree = []
        try:
            process_tree = self.list_process_tree()
        except Exception as exc:
            warnings.append(f"pstree unavailable: {exc}")

        network_connections = []
        try:
            network_connections = self.list_network_connections()
            network_backend = "windows.netscan.NetScan"
        except Exception as exc:
            warnings.append(f"netscan unavailable: {exc}")
            try:
                network_connections = self._normalize_records(self._run_plugin("windows.netstat.NetStat"))
                network_backend = "windows.netstat.NetStat"
                warnings.append("Used netstat fallback because netscan was not supported for this capture.")
            except Exception as fallback_exc:
                network_connections = []
                warnings.append(f"netstat fallback unavailable: {fallback_exc}")

        return {
            "image_path": os.path.abspath(self.image_path),
            "processes": process_list,
            "process_tree": process_tree,
            "network_connections": network_connections,
            "network_backend": network_backend,
            "warnings": warnings,
            "summary": {
                "process_count": len(process_list),
                "process_tree_count": len(process_tree),
                "network_connection_count": len(network_connections),
                "network_backend": network_backend,
                "warning_count": len(warnings),
            },
        }

    def sanity_check(self) -> Dict[str, Any]:
        """Run a lightweight preflight check to confirm the capture behaves like RAM."""
        image_path = Path(self.image_path)
        exists = image_path.is_file()
        size_bytes = image_path.stat().st_size if exists else 0
        extension_supported = image_path.suffix.lower() in SUPPORTED_RAM_EXTENSIONS
        likely_memory_capture = bool(exists and extension_supported and size_bytes >= MIN_RAM_CAPTURE_SIZE_BYTES)

        report: Dict[str, Any] = {
            "image_path": os.path.abspath(self.image_path),
            "exists": exists,
            "size_bytes": size_bytes,
            "extension_supported": extension_supported,
            "likely_memory_capture": likely_memory_capture,
            "plugin_check": None,
            "status": "fail",
            "notes": [],
        }

        if not exists:
            report["notes"].append("File not found.")
            return report

        if not extension_supported:
            report["notes"].append("Unsupported file extension for RAM analysis.")

        if not likely_memory_capture:
            if size_bytes < MIN_RAM_CAPTURE_SIZE_BYTES:
                report["notes"].append("File is smaller than the minimum size usually expected for a RAM capture.")
            if report["notes"]:
                report["notes"].append("The file may still be valid, but it does not look like a strong RAM candidate yet.")
            return report

        try:
            info_records = self._normalize_records(self._run_plugin("windows.info.Info"))
            report["plugin_check"] = {
                "plugin": "windows.info.Info",
                "status": "ok",
                "record_count": len(info_records),
                "sample": info_records[:3],
            }
            report["status"] = "pass"
            report["notes"].append("Volatility parsed the image successfully using the Info plugin.")
        except Exception as exc:
            report["plugin_check"] = {
                "plugin": "windows.info.Info",
                "status": "error",
                "error": str(exc),
            }
            report["notes"].append("Volatility could not initialize this file as a memory image.")

        return report

    def list_processes(self) -> List[Dict[str, Any]]:
        """Return a normalized list of process records from pslist."""
        try:
            output = self._run_plugin("windows.pslist.PsList")
            return self._normalize_records(output)
        except Exception as exc:
            raise RuntimeError(f"Failed to list processes: {exc}")

    def list_process_tree(self) -> List[Dict[str, Any]]:
        """Return a normalized list of process-tree records from pstree."""
        try:
            output = self._run_plugin("windows.pstree.PsTree")
            return self._normalize_records(output)
        except Exception as exc:
            raise RuntimeError(f"Failed to list process tree: {exc}")

    def list_network_connections(self) -> List[Dict[str, Any]]:
        """Return a normalized list of network connection records from netscan."""
        try:
            output = self._run_plugin("windows.netscan.NetScan")
            return self._normalize_records(output)
        except Exception as exc:
            raise RuntimeError(f"Failed to list network connections: {exc}")

    def _validate_image_path(self):
        """Raise FileNotFoundError/ValueError if the path is invalid, otherwise None."""
        if not Path(self.image_path).is_file():
            raise FileNotFoundError(f"RAM image not found: {self.image_path}")
        if not self.is_supported_image():
            raise ValueError(
                "Expected a RAM capture path such as .raw, .mem, .dmp, .vmem, .lime, or .aff4"
            )
        return None

    def _run_plugin(self, plugin_name: str, extra_args: Sequence[str] | None = None) -> Any:
        """Execute a Volatility 3 plugin and return the parsed renderer output.

        Output is streamed to a temporary file rather than buffered entirely in
        memory via ``capture_output=True``. This avoids holding a second copy of
        a large capture's renderer output in the Flask worker's RAM and prevents
        a Volatility crash/OOM from taking down the request handler.
        """
        import tempfile

        extra_args = list(extra_args or [])

        command = [
            sys.executable,
            "-c",
            VOLATILITY_DRIVER_SNIPPET,
            "-q",
            "-f",
            self.image_path,
            "-r",
            "json",
            plugin_name,
            *extra_args,
        ]

        # Stream Volatility's stdout/stderr to disk instead of buffering in RAM.
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".vol.stdout", delete=False, encoding="utf-8"
        ) as out_file, tempfile.NamedTemporaryFile(
            mode="w+", suffix=".vol.stderr", delete=False, encoding="utf-8"
        ) as err_file:
            out_path = out_file.name
            err_path = err_file.name
            try:
                completed = subprocess.run(
                    command,
                    stdout=out_file,
                    stderr=err_file,
                    check=False,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"Volatility plugin timed out: {plugin_name}") from exc

        try:
            with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
                stderr = fh.read().strip()
            with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                stdout = fh.read().strip()
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
            try:
                os.unlink(err_path)
            except OSError:
                pass

        if completed.returncode != 0:
            message = stderr or stdout or f"Volatility exited with code {completed.returncode}"
            # Extract only the last meaningful error line from the traceback
            lines = message.strip().splitlines()
            error_lines = [line for line in lines if line and not line.startswith("  ") and not line.startswith("File ")]
            short_message = error_lines[-1] if error_lines else lines[-1]
            raise RuntimeError(short_message)

        if not stdout:
            return []

        return self._parse_renderer_output(stdout)

    def _parse_renderer_output(self, raw_output: str) -> Any:
        """Parse the Volatility JSON renderer output, falling back defensively."""
        text = raw_output.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start_candidates = [idx for idx in (text.find("["), text.find("{")) if idx != -1]
            if start_candidates:
                start = min(start_candidates)
                end = max(text.rfind("]"), text.rfind("}"))
                if end > start:
                    candidate = text[start : end + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        pass

        return {"raw_output": text}

    def _normalize_records(self, payload: Any) -> List[Dict[str, Any]]:
        """Flatten Volatility renderer output into a list of plain dictionaries."""
        records: List[Dict[str, Any]] = []
        seen: set[str] = set()

        def walk(node: Any) -> None:
            if node is None:
                return

            if isinstance(node, list):
                for item in node:
                    walk(item)
                return

            if isinstance(node, dict):
                record = {key: value for key, value in node.items() if key != "__children"}
                if record:
                    marker = json.dumps(record, sort_keys=True, default=str)
                    if marker not in seen:
                        seen.add(marker)
                        records.append(record)

                children = node.get("__children")
                if isinstance(children, list):
                    for child in children:
                        walk(child)
                else:
                    for value in node.values():
                        if isinstance(value, (dict, list)):
                            walk(value)

        walk(payload)
        return records


def analyze_ram_dump(image_path: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """Convenience wrapper for callers that do not need the class API."""
    module = RAMModule(image_path, timeout_seconds=timeout_seconds)
    try:
        return module.analyze()
    except FileNotFoundError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "image_path": os.path.abspath(image_path),
        }
    except ValueError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "image_path": os.path.abspath(image_path),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "image_path": os.path.abspath(image_path),
        }


def sanity_check_ram_capture(image_path: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """Convenience wrapper for the RAM preflight check."""
    return RAMModule(image_path, timeout_seconds=timeout_seconds).sanity_check()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyze a RAM image with Volatility 3")
    parser.add_argument("image_path", help="Path to a RAM capture such as .raw, .mem, or .dmp")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="Volatility timeout in seconds")
    args = parser.parse_args()

    result = analyze_ram_dump(args.image_path, timeout_seconds=args.timeout)
    print(json.dumps(result, indent=2, sort_keys=True, default=str))