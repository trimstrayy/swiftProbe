"""Log parsing helpers for SwiftProbe.

This module extracts file metadata, parses Windows EVTX files when available,
and performs best-effort USB and file-transfer activity discovery from local
system event logs.
"""
from __future__ import annotations

import mimetypes
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    from backend.hasher import hash_file
except ImportError:  # pragma: no cover - supports running from the backend folder
    from hasher import hash_file


USB_KEYWORDS = (
    "usb",
    "usbstor",
    "removable",
    "deviceinstall",
    "plug and play",
    "pnp",
    "volume",
    "drive",
)

TRANSFER_KEYWORDS = (
    "copy",
    "file transfer",
    "transfer",
    "move",
    "write",
    "read",
    "mount",
    "eject",
    "import",
    "export",
)


def _utc_iso(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None

    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _event_text(event: Dict[str, Any]) -> str:
    event_data = event.get("event_data") or {}
    raw_xml = event.get("raw_xml") or ""
    parts = [
        str(event.get("provider") or ""),
        str(event.get("channel") or ""),
        str(event.get("computer") or ""),
        str(event.get("event_id") or ""),
        str(event.get("level") or ""),
        str(event.get("timestamp") or ""),
        raw_xml,
    ]
    if isinstance(event_data, dict):
        parts.extend(str(value) for value in event_data.values())

    return " ".join(parts).lower()


def _parse_event_xml(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)
    system = root.find("{*}System")
    event_data = root.find("{*}EventData")
    user_data = root.find("{*}UserData")

    data_fields: Dict[str, Any] = {}
    if event_data is not None:
        for index, data_element in enumerate(event_data.findall("{*}Data")):
            field_name = data_element.attrib.get("Name") or f"Data{index}"
            data_fields[field_name] = (data_element.text or "").strip()

    user_data_fields: Dict[str, Any] = {}
    if user_data is not None:
        for child in user_data.iter():
            if child is user_data:
                continue
            if list(child):
                continue
            if child.text:
                tag = child.tag.rsplit("}", 1)[-1]
                user_data_fields[tag] = child.text.strip()

    event_id = None
    provider = None
    channel = None
    computer = None
    level = None
    task = None
    opcode = None
    keywords = None
    record_id = None
    timestamp = None

    if system is not None:
        event_id_node = system.find("{*}EventID")
        if event_id_node is not None and event_id_node.text:
            try:
                event_id = int(event_id_node.text)
            except ValueError:
                event_id = event_id_node.text.strip()

        provider_node = system.find("{*}Provider")
        if provider_node is not None:
            provider = provider_node.attrib.get("Name") or provider_node.attrib.get("Guid")

        channel_node = system.find("{*}Channel")
        if channel_node is not None and channel_node.text:
            channel = channel_node.text.strip()

        computer_node = system.find("{*}Computer")
        if computer_node is not None and computer_node.text:
            computer = computer_node.text.strip()

        level_node = system.find("{*}Level")
        if level_node is not None and level_node.text:
            level = level_node.text.strip()

        task_node = system.find("{*}Task")
        if task_node is not None and task_node.text:
            task = task_node.text.strip()

        opcode_node = system.find("{*}Opcode")
        if opcode_node is not None and opcode_node.text:
            opcode = opcode_node.text.strip()

        keywords_node = system.find("{*}Keywords")
        if keywords_node is not None and keywords_node.text:
            keywords = keywords_node.text.strip()

        record_id_node = system.find("{*}EventRecordID")
        if record_id_node is not None and record_id_node.text:
            record_id = record_id_node.text.strip()

        time_created_node = system.find("{*}TimeCreated")
        if time_created_node is not None:
            timestamp = time_created_node.attrib.get("SystemTime")

    return {
        "event_id": event_id,
        "record_id": record_id,
        "provider": provider,
        "channel": channel,
        "computer": computer,
        "level": level,
        "task": task,
        "opcode": opcode,
        "keywords": keywords,
        "timestamp": timestamp,
        "event_data": data_fields,
        "user_data": user_data_fields,
        "raw_xml": xml_text,
    }


def _default_event_log_paths() -> List[str]:
    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = [
        windows_root / "System32" / "winevt" / "Logs" / "System.evtx",
        windows_root / "System32" / "winevt" / "Logs" / "Security.evtx",
        windows_root / "System32" / "winevt" / "Logs" / "Application.evtx",
        windows_root / "System32" / "winevt" / "Logs" / "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
        windows_root / "System32" / "winevt" / "Logs" / "Microsoft-Windows-UserPnp%4DeviceInstall.evtx",
        windows_root / "System32" / "winevt" / "Logs" / "Microsoft-Windows-USB-USBHUB3%4Operational.evtx",
        windows_root / "System32" / "winevt" / "Logs" / "Microsoft-Windows-Partition%4Diagnostic.evtx",
    ]
    return [str(candidate) for candidate in candidates if candidate.exists()]


def extract_file_metadata(file_path: str) -> Dict[str, Any]:
    """Return file integrity and filesystem metadata for an uploaded artifact."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    stat_result = path.stat()
    hash_meta = hash_file(str(path))
    mime_type, encoding = mimetypes.guess_type(path.name)

    return {
        **hash_meta,
        "extension": path.suffix.lower(),
        "suffixes": path.suffixes,
        "mime_type": mime_type,
        "encoding": encoding,
        "created_time": _utc_iso(stat_result.st_ctime),
        "accessed_time": _utc_iso(stat_result.st_atime),
        "modified_time": _utc_iso(stat_result.st_mtime),
    }


def parse_event_log(log_path: str) -> List[Dict]:
    """Parse a Windows EVTX file and return a list of event dictionaries.

    This function is intentionally lightweight so it works when `python-evtx`
    is not installed; when available it will produce parsed XML for each
    record.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    try:
        import Evtx
    except Exception:
        # Evtx not installed: return an empty list and allow the caller to
        # fall back to offline conversion tools.
        return []

    events = []
    with Evtx.Evtx(str(path)) as evtx:
        for record in evtx.records():
            try:
                xml = record.xml()
                parsed_event = _parse_event_xml(xml)
                parsed_event["log_path"] = str(path)
                events.append(parsed_event)
            except Exception:
                continue

    return events


def analyze_event_logs(log_paths: Optional[Sequence[str]] = None, limit: int = 50) -> Dict[str, Any]:
    """Inspect EVTX files for USB and file-transfer activity."""
    candidate_paths = [str(path) for path in (log_paths or _default_event_log_paths()) if path]
    parsed_logs: List[Dict[str, Any]] = []

    for log_path in candidate_paths:
        try:
            parsed_logs.extend(parse_event_log(log_path))
        except Exception:
            continue

    usb_events: List[Dict[str, Any]] = []
    transfer_events: List[Dict[str, Any]] = []

    for event in parsed_logs:
        text = _event_text(event)
        if any(keyword in text for keyword in USB_KEYWORDS):
            usb_events.append(event)
        if any(keyword in text for keyword in TRANSFER_KEYWORDS):
            transfer_events.append(event)

    def _limited(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return list(events)[:limit]

    return {
        "logs_scanned": candidate_paths,
        "event_count": len(parsed_logs),
        "usb_connection_events": _limited(usb_events),
        "file_transfer_events": _limited(transfer_events),
        "usb_connection_count": len(usb_events),
        "file_transfer_count": len(transfer_events),
    }


def analyze_uploaded_artifact(
    file_path: str,
    case_id: Optional[str] = None,
    log_paths: Optional[Sequence[str]] = None,
    file_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return file metadata plus log intelligence for a newly uploaded artifact."""
    file_metadata = file_metadata or extract_file_metadata(file_path)
    event_analysis = analyze_event_logs(log_paths=log_paths)
    uploaded_events: List[Dict[str, Any]] = []

    if file_metadata.get("extension") == ".evtx":
        try:
            uploaded_events = parse_event_log(file_path)
        except Exception:
            uploaded_events = []

    return {
        "case_id": case_id,
        "artifact_path": str(Path(file_path).resolve()),
        "file_metadata": file_metadata,
        "event_log_scan": event_analysis,
        "uploaded_event_count": len(uploaded_events),
        "uploaded_events": uploaded_events[:25],
        "summary": {
            "source_filename": file_metadata.get("filename"),
            "source_hash": file_metadata.get("hash"),
            "source_size_bytes": file_metadata.get("size", 0),
            "usb_events_found": event_analysis["usb_connection_count"],
            "file_transfer_events_found": event_analysis["file_transfer_count"],
            "uploaded_log_events_found": len(uploaded_events),
        },
    }


class LogModule:
    """Facade for log metadata and device activity analysis."""

    def extract_file_metadata(self, file_path: str) -> Dict[str, Any]:
        return extract_file_metadata(file_path)

    def parse_event_log(self, log_path: str) -> List[Dict]:
        return parse_event_log(log_path)

    def analyze_event_logs(self, log_paths: Optional[Sequence[str]] = None, limit: int = 50) -> Dict[str, Any]:
        return analyze_event_logs(log_paths=log_paths, limit=limit)

    def analyze_uploaded_artifact(
        self,
        file_path: str,
        case_id: Optional[str] = None,
        log_paths: Optional[Sequence[str]] = None,
        file_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return analyze_uploaded_artifact(file_path, case_id=case_id, log_paths=log_paths, file_metadata=file_metadata)
