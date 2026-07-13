"""Windows log analysis helpers for SwiftProbe.

This module performs best-effort forensic log analysis for Windows event logs.
It extracts file metadata, parses EVTX/XML logs, classifies USB and file
transfer activity, attempts user attribution from common event fields, and can
persist complete analysis runs to Supabase.
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from backend.core.supabase_db import get_supabase_client
from backend.hasher import hash_file, normalize_sha256


WINDOWS_DEFAULT_LOG_PATHS = (
    "System32/winevt/Logs/System.evtx",
    "System32/winevt/Logs/Security.evtx",
    "System32/winevt/Logs/Application.evtx",
    "System32/winevt/Logs/Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
    "System32/winevt/Logs/Microsoft-Windows-UserPnp%4DeviceInstall.evtx",
    "System32/winevt/Logs/Microsoft-Windows-USB-USBHUB3%4Operational.evtx",
    "System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx",
)

USB_PROVIDER_HINTS = (
    "usb",
    "usbstor",
    "userpnp",
    "driverframeworks-usermode",
    "kernel-pnp",
    "partition",
    "volume",
)

USB_KEYWORDS = (
    "usb",
    "usbstor",
    "removable",
    "plug and play",
    "pnp",
    "mount",
    "mounted",
    "eject",
    "remove",
    "disconnect",
    "external device",
    "device install",
)

TRANSFER_KEYWORDS = (
    "copy",
    "transfer",
    "move",
    "write",
    "read",
    "import",
    "export",
    "writefile",
    "readfile",
    "created",
    "completed",
    "success",
    "finished",
)

USER_FIELD_NAMES = (
    "SubjectUserName",
    "TargetUserName",
    "AccountName",
    "UserName",
    "CallerUserName",
    "User",
    "SecurityUserID",
    "SubjectDomainName",
    "TargetDomainName",
    "Domain",
    "UserDomain",
    "SubjectLogonId",
    "TargetLogonId",
    "LogonId",
    "UserId",
    "SID",
    "UserSID",
    "ProcessName",
    "Image",
    "CommandLine",
    "SourceProcessName",
)

USB_EVENT_IDS = {
    6416,
    20001,
    20003,
    20004,
    2100,
    2101,
    2102,
    2103,
    2104,
    2105,
    2106,
}

FILE_EVENT_IDS = {
    4656,
    4660,
    4663,
    4664,
    4665,
    4670,
    4698,
    4702,
    5140,
    5145,
    5156,
    5158,
}


@dataclass
class AnalysisState:
    case_id: Optional[str]
    source_path: Optional[str]
    source_kind: str


def _utc_iso(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None

    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _safe_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_safe_value(item) for item in value]

    return str(value)


def _default_event_log_paths() -> List[str]:
    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    return [str(windows_root / path) for path in WINDOWS_DEFAULT_LOG_PATHS if (windows_root / path).exists()]


def _iter_candidate_event_elements(xml_text: str) -> List[str]:
    root = ET.fromstring(xml_text)
    if root.tag.endswith("Event"):
        return [xml_text]

    events = []
    for element in root.findall(".//{*}Event"):
        events.append(ET.tostring(element, encoding="unicode"))
    return events


def _parse_event_sections(xml_text: str) -> Dict[str, Any]:
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
            if child is user_data or list(child):
                continue
            if child.text:
                tag = child.tag.rsplit("}", 1)[-1]
                user_data_fields[tag] = child.text.strip()

    system_fields: Dict[str, Any] = {}
    if system is not None:
        for child in system:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "Provider":
                system_fields["ProviderName"] = child.attrib.get("Name") or child.attrib.get("Guid")
            elif tag == "TimeCreated":
                system_fields["SystemTime"] = child.attrib.get("SystemTime")
            elif child.text:
                system_fields[tag] = child.text.strip()

    event_id = None
    if system_fields.get("EventID"):
        try:
            event_id = int(system_fields["EventID"])
        except Exception:
            event_id = system_fields["EventID"]

    timestamp = system_fields.get("SystemTime")
    if timestamp is None:
        time_created = system.find("{*}TimeCreated") if system is not None else None
        if time_created is not None:
            timestamp = time_created.attrib.get("SystemTime")

    provider = system_fields.get("ProviderName")
    channel = system_fields.get("Channel")
    computer = system_fields.get("Computer")
    level = system_fields.get("Level")
    task = system_fields.get("Task")
    opcode = system_fields.get("Opcode")
    keywords = system_fields.get("Keywords")
    record_id = system_fields.get("EventRecordID")

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
        "system_data": system_fields,
        "raw_xml": xml_text,
    }


def _flatten_text(event: Dict[str, Any]) -> str:
    parts = [
        str(event.get("provider") or ""),
        str(event.get("channel") or ""),
        str(event.get("computer") or ""),
        str(event.get("event_id") or ""),
        str(event.get("level") or ""),
        str(event.get("task") or ""),
        str(event.get("opcode") or ""),
        str(event.get("keywords") or ""),
        str(event.get("timestamp") or ""),
        str(event.get("raw_xml") or ""),
    ]

    for field_map in (event.get("event_data") or {}, event.get("user_data") or {}, event.get("system_data") or {}):
        if isinstance(field_map, dict):
            parts.extend(str(value) for value in field_map.values())

    return " ".join(parts).lower()


def _first_nonempty(mapping: Dict[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _extract_user_context(event: Dict[str, Any]) -> Dict[str, Any]:
    event_data = event.get("event_data") or {}
    user_data = event.get("user_data") or {}
    system_data = event.get("system_data") or {}

    merged = {**system_data, **event_data, **user_data}
    user_name = _first_nonempty(merged, [
        "SubjectUserName",
        "TargetUserName",
        "AccountName",
        "UserName",
        "CallerUserName",
        "User",
        "UserId",
    ])
    user_domain = _first_nonempty(merged, [
        "SubjectDomainName",
        "TargetDomainName",
        "Domain",
        "UserDomain",
    ])
    user_sid = _first_nonempty(merged, ["SecurityUserID", "UserSID", "SID", "TargetUserSid", "SubjectUserSid"])
    logon_id = _first_nonempty(merged, ["SubjectLogonId", "TargetLogonId", "LogonId"])
    process_name = _first_nonempty(merged, ["ProcessName", "Image", "CommandLine", "SourceProcessName"])

    user_summary = None
    if user_name and user_domain:
        user_summary = f"{user_domain}\\{user_name}"
    elif user_name:
        user_summary = user_name

    return {
        "user_name": user_name,
        "user_domain": user_domain,
        "user_sid": user_sid,
        "logon_id": logon_id,
        "process_name": process_name,
        "user_summary": user_summary,
    }


def _classify_event(event: Dict[str, Any]) -> Tuple[str, str, float, List[str], List[str]]:
    text = _flatten_text(event)
    event_id = event.get("event_id")
    provider = str(event.get("provider") or "").lower()
    tags: List[str] = []
    indicators: List[str] = []
    activity_type = "log_event"
    activity_stage = "observed"
    confidence = 0.15

    if provider and any(hint in provider for hint in USB_PROVIDER_HINTS):
        tags.append("usb")
        indicators.append(f"provider:{provider}")
        confidence = max(confidence, 0.65)

    if event_id in USB_EVENT_IDS:
        tags.append("usb")
        indicators.append(f"event_id:{event_id}")
        confidence = max(confidence, 0.9)

    if any(keyword in text for keyword in USB_KEYWORDS):
        tags.append("usb")
        indicators.append("keyword:usb")
        confidence = max(confidence, 0.75)

    if any(keyword in text for keyword in TRANSFER_KEYWORDS):
        tags.append("file_transfer")
        indicators.append("keyword:transfer")
        confidence = max(confidence, 0.7)

    if event_id in FILE_EVENT_IDS:
        tags.append("file_transfer")
        indicators.append(f"event_id:{event_id}")
        confidence = max(confidence, 0.82)

    event_data = event.get("event_data") or {}
    for field in ("ObjectName", "TargetFilename", "SourceFilename", "DestinationFilename", "FileName", "ShareName", "DeviceName"):
        if event_data.get(field):
            indicators.append(f"field:{field}")
            if field in {"ObjectName", "TargetFilename", "SourceFilename", "DestinationFilename", "FileName"}:
                tags.append("file_transfer")

    if event_data.get("UserName") or event_data.get("SubjectUserName") or event_data.get("TargetUserName"):
        tags.append("user_attributed")
        indicators.append("field:user")
        confidence = max(confidence, 0.8)

    if "external device" in text or "new external device" in text or event_id == 6416:
        activity_type = "usb_connected"
        activity_stage = "connected"
        confidence = max(confidence, 0.95)
    elif "mounted" in text or "volume" in text or "drive letter" in text:
        activity_type = "usb_mounted"
        activity_stage = "mounted"
        confidence = max(confidence, 0.85)
    elif "eject" in text or "remove" in text or "disconnect" in text or "unplug" in text:
        activity_type = "usb_removed"
        activity_stage = "removed"
        confidence = max(confidence, 0.84)
    elif any(token in text for token in ("completed", "success", "finished")) and "file_transfer" in tags:
        activity_type = "file_transfer_completed"
        activity_stage = "completed"
        confidence = max(confidence, 0.85)
    elif "file_transfer" in tags:
        activity_type = "file_transfer_initiated"
        activity_stage = "initiated"
        confidence = max(confidence, 0.8)
    elif "usb" in tags:
        activity_type = "usb_activity"
        activity_stage = "detected"

    if not tags:
        tags.append("observed")

    return activity_type, activity_stage, confidence, tags, indicators


def _normalize_event(event: Dict[str, Any], log_path: str, record_index: int, source_kind: str) -> Dict[str, Any]:
    user_context = _extract_user_context(event)
    activity_type, activity_stage, confidence, tags, indicators = _classify_event(event)
    event_data = _safe_value(event.get("event_data") or {})
    user_data = _safe_value(event.get("user_data") or {})
    system_data = _safe_value(event.get("system_data") or {})

    summary_parts = []
    if user_context.get("user_summary"):
        summary_parts.append(user_context["user_summary"])
    if activity_type != "log_event":
        summary_parts.append(activity_type.replace("_", " "))
    if event.get("provider"):
        summary_parts.append(str(event["provider"]))
    if event.get("event_id") is not None:
        summary_parts.append(f"event {event['event_id']}")
    summary = " | ".join(summary_parts) if summary_parts else "Observed log event"

    return {
        "log_path": log_path,
        "source_kind": source_kind,
        "record_index": record_index,
        "event_id": event.get("event_id"),
        "record_id": event.get("record_id"),
        "provider": event.get("provider"),
        "channel": event.get("channel"),
        "computer": event.get("computer"),
        "level": event.get("level"),
        "task": event.get("task"),
        "opcode": event.get("opcode"),
        "keywords": event.get("keywords"),
        "timestamp": event.get("timestamp"),
        "user_context": user_context,
        "user_name": user_context.get("user_name"),
        "user_domain": user_context.get("user_domain"),
        "user_sid": user_context.get("user_sid"),
        "logon_id": user_context.get("logon_id"),
        "process_name": user_context.get("process_name"),
        "activity_type": activity_type,
        "activity_stage": activity_stage,
        "activity_tags": tags,
        "confidence": confidence,
        "indicators": indicators,
        "summary": summary,
        "event_data": event_data,
        "user_data": user_data,
        "system_data": system_data,
        "raw_xml": event.get("raw_xml"),
    }


def _event_sort_key(event: Dict[str, Any]) -> Tuple[str, int]:
    return (str(event.get("timestamp") or ""), int(event.get("record_index") or 0))


def _select_events(events: Sequence[Dict[str, Any]], predicate) -> List[Dict[str, Any]]:
    return [event for event in events if predicate(event)]


def _summarize_users(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counter: Counter[str] = Counter()
    for event in events:
        user_summary = event.get("user_context", {}).get("user_summary")
        if user_summary:
            counter[user_summary] += 1
    return [{"user": user, "count": count} for user, count in counter.most_common()]


def _summarize_activity(events: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counter: Counter[str] = Counter()
    for event in events:
        counter[str(event.get("activity_type") or "log_event")] += 1
    return dict(counter)


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


def _parse_with_evtx(log_path: Path) -> List[str]:
    try:
        import Evtx
    except Exception:
        return []

    xml_records: List[str] = []
    with Evtx.Evtx(str(log_path)) as evtx:
        for record in evtx.records():
            try:
                xml_records.append(record.xml())
            except Exception:
                continue
    return xml_records


def _parse_xml_file(log_path: Path) -> List[str]:
    tree = ET.parse(str(log_path))
    root = tree.getroot()
    if root.tag.endswith("Event"):
        return [ET.tostring(root, encoding="unicode")]
    return [ET.tostring(event, encoding="unicode") for event in root.findall(".//{*}Event")]


def parse_event_log(log_path: str) -> List[Dict[str, Any]]:
    """Parse a Windows EVTX/XML file and return normalized event dictionaries."""
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    suffix = path.suffix.lower()
    if suffix == ".evtx":
        xml_records = _parse_with_evtx(path)
    elif suffix == ".xml":
        xml_records = _parse_xml_file(path)
    else:
        return []

    events: List[Dict[str, Any]] = []
    for index, xml_text in enumerate(xml_records):
        try:
            parsed = _parse_event_sections(xml_text)
            parsed["log_path"] = str(path)
            parsed["record_index"] = index
            events.append(parsed)
        except Exception:
            continue

    return events


def _collect_events_from_paths(log_paths: Sequence[str], source_kind: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    parsed_logs: List[Dict[str, Any]] = []
    scanned_paths: List[str] = []

    for log_path in log_paths:
        if not log_path:
            continue
        path = Path(log_path)
        if not path.exists():
            continue
        scanned_paths.append(str(path))
        try:
            raw_events = parse_event_log(str(path))
        except Exception:
            raw_events = []

        for index, raw_event in enumerate(raw_events):
            parsed = _normalize_event(raw_event, str(path), index, source_kind)
            parsed_logs.append(parsed)

    parsed_logs.sort(key=_event_sort_key)
    return parsed_logs, scanned_paths


def analyze_event_logs(
    log_paths: Optional[Sequence[str]] = None,
    limit: int = 100,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect EVTX/XML files for USB, file-transfer, and user activity."""
    candidate_paths = [str(path) for path in (log_paths or _default_event_log_paths()) if path]
    events, scanned_paths = _collect_events_from_paths(candidate_paths, source_kind="device_scan")

    usb_events = _select_events(events, lambda event: "usb" in (event.get("activity_tags") or []))
    file_transfer_events = _select_events(events, lambda event: "file_transfer" in (event.get("activity_tags") or []))
    user_attribution_events = _select_events(events, lambda event: bool(event.get("user_context", {}).get("user_summary")))
    usb_connected_events = _select_events(events, lambda event: event.get("activity_type") == "usb_connected")
    usb_mounted_events = _select_events(events, lambda event: event.get("activity_type") == "usb_mounted")
    usb_removed_events = _select_events(events, lambda event: event.get("activity_type") == "usb_removed")
    file_transfer_started_events = _select_events(events, lambda event: event.get("activity_type") == "file_transfer_initiated")
    file_transfer_completed_events = _select_events(events, lambda event: event.get("activity_type") == "file_transfer_completed")

    activity_counts = _summarize_activity(events)
    user_counts = _summarize_users(events)
    timeline = events[:limit]

    return {
        "case_id": case_id,
        "logs_scanned": scanned_paths,
        "event_count": len(events),
        "usb_connection_count": len(usb_connected_events),
        "usb_mounted_count": len(usb_mounted_events),
        "usb_removed_count": len(usb_removed_events),
        "file_transfer_started_count": len(file_transfer_started_events),
        "file_transfer_completed_count": len(file_transfer_completed_events),
        "file_transfer_count": len(file_transfer_events),
        "user_attribution_count": len(user_attribution_events),
        "activity_counts": activity_counts,
        "user_counts": user_counts,
        "timeline": timeline,
        "events": timeline,
        "usb_connection_events": usb_connected_events[:limit],
        "usb_mounted_events": usb_mounted_events[:limit],
        "usb_removed_events": usb_removed_events[:limit],
        "file_transfer_events": file_transfer_events[:limit],
        "file_transfer_started_events": file_transfer_started_events[:limit],
        "file_transfer_completed_events": file_transfer_completed_events[:limit],
        "user_attribution_events": user_attribution_events[:limit],
        "summary": {
            "event_count": len(events),
            "usb_connection_count": len(usb_connected_events),
            "usb_mounted_count": len(usb_mounted_events),
            "usb_removed_count": len(usb_removed_events),
            "file_transfer_started_count": len(file_transfer_started_events),
            "file_transfer_completed_count": len(file_transfer_completed_events),
            "user_attribution_count": len(user_attribution_events),
            "unique_users": len(user_counts),
            "logs_scanned": len(scanned_paths),
        },
    }


def analyze_uploaded_artifact(
    file_path: str,
    case_id: Optional[str] = None,
    log_paths: Optional[Sequence[str]] = None,
    file_metadata: Optional[Dict[str, Any]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Return file metadata plus device-log intelligence for a newly uploaded artifact."""
    file_metadata = file_metadata or extract_file_metadata(file_path)
    uploaded_events: List[Dict[str, Any]] = []
    source_kind = "uploaded_file"

    if file_metadata.get("extension") in {".evtx", ".xml"}:
        try:
            raw_uploaded_events = parse_event_log(file_path)
            uploaded_events = [
                _normalize_event(event, str(Path(file_path)), index, source_kind)
                for index, event in enumerate(raw_uploaded_events)
            ]
        except Exception:
            uploaded_events = []

    event_log_scan = analyze_event_logs(log_paths=log_paths, limit=limit, case_id=case_id)
    merged_users = {
        item.get("user_context", {}).get("user_summary")
        for item in (event_log_scan.get("user_attribution_events") or []) + uploaded_events
        if item.get("user_context", {}).get("user_summary")
    }

    return {
        "case_id": case_id,
        "artifact_path": str(Path(file_path).resolve()),
        "file_metadata": file_metadata,
        "event_log_scan": event_log_scan,
        "uploaded_event_count": len(uploaded_events),
        "uploaded_events": uploaded_events[:limit],
        "identified_users": sorted(merged_users),
        "summary": {
            "source_filename": file_metadata.get("filename"),
            "source_hash": file_metadata.get("hash"),
            "source_size_bytes": file_metadata.get("size", 0),
            "usb_events_found": event_log_scan["summary"]["usb_connection_count"],
            "file_transfer_events_found": event_log_scan["summary"]["file_transfer_started_count"]
            + event_log_scan["summary"]["file_transfer_completed_count"],
            "user_attributions_found": event_log_scan["summary"]["user_attribution_count"],
            "uploaded_log_events_found": len(uploaded_events),
        },
    }


def _chunked(values: Sequence[Dict[str, Any]], size: int = 100) -> Iterable[List[Dict[str, Any]]]:
    for index in range(0, len(values), size):
        yield list(values[index : index + size])


def persist_log_analysis(analysis: Dict[str, Any], source_path: Optional[str] = None) -> Dict[str, Any]:
    """Persist a log analysis run and its events to Supabase.

    This is best-effort. If the database tables are missing or Supabase is not
    configured, the function returns a structured response and keeps local data.
    """
    client = get_supabase_client()
    if client is None:
        return {"ok": False, "error": "Supabase is not configured", "session": None, "events_inserted": 0}

    file_metadata = analysis.get("file_metadata") or {}
    event_scan = analysis.get("event_log_scan") or {}
    summary = analysis.get("summary") or {}
    session_payload = {
        "case_id": analysis.get("case_id"),
        "analysis_source": analysis.get("analysis_source") or ("uploaded_file" if analysis.get("uploaded_event_count") else "device_scan"),
        "source_path": source_path or analysis.get("artifact_path"),
        "source_filename": file_metadata.get("filename"),
        "source_sha256": file_metadata.get("hash"),
        "source_size": file_metadata.get("size", 0),
        "source_mtime": file_metadata.get("mtime") or file_metadata.get("modified_time"),
        "logs_scanned": event_scan.get("logs_scanned") or [],
        "event_count": event_scan.get("summary", {}).get("event_count") or event_scan.get("event_count") or 0,
        "usb_connection_count": event_scan.get("summary", {}).get("usb_connection_count") or event_scan.get("usb_connection_count") or 0,
        "usb_mounted_count": event_scan.get("summary", {}).get("usb_mounted_count") or event_scan.get("usb_mounted_count") or 0,
        "usb_removed_count": event_scan.get("summary", {}).get("usb_removed_count") or event_scan.get("usb_removed_count") or 0,
        "file_transfer_started_count": event_scan.get("summary", {}).get("file_transfer_started_count") or event_scan.get("file_transfer_started_count") or 0,
        "file_transfer_completed_count": event_scan.get("summary", {}).get("file_transfer_completed_count") or event_scan.get("file_transfer_completed_count") or 0,
        "user_attribution_count": event_scan.get("summary", {}).get("user_attribution_count") or event_scan.get("user_attribution_count") or 0,
        "activity_counts": event_scan.get("activity_counts") or {},
        "user_counts": event_scan.get("user_counts") or [],
        "summary": summary,
        "file_metadata": file_metadata,
        "uploaded_event_count": analysis.get("uploaded_event_count") or 0,
        "uploaded_events": analysis.get("uploaded_events") or [],
        "identified_users": analysis.get("identified_users") or [],
    }

    try:
        session_response = client.table("log_analysis_sessions").insert(_safe_value(session_payload)).execute()
        session_rows = getattr(session_response, "data", []) or []
        session_row = session_rows[0] if session_rows else {}
        session_id = session_row.get("id")
    except Exception as exc:
        return {"ok": False, "error": str(exc), "session": None, "events_inserted": 0}

    event_rows: List[Dict[str, Any]] = []
    for event in event_scan.get("events", []) or []:
        event_rows.append(
            _event_row_payload(session_id, analysis.get("case_id"), event, source_kind="device_scan")
        )
    for event in analysis.get("uploaded_events", []) or []:
        event_rows.append(
            _event_row_payload(session_id, analysis.get("case_id"), event, source_kind="uploaded_file")
        )

    inserted = 0
    if event_rows:
        for chunk in _chunked(event_rows, size=100):
            try:
                client.table("log_events").insert(_safe_value(chunk)).execute()
                inserted += len(chunk)
            except Exception:
                # keep local results even if detailed inserts fail
                continue

    return {
        "ok": True,
        "session": session_row,
        "events_inserted": inserted,
    }


def _event_row_payload(session_id: Optional[int], case_id: Optional[str], event: Dict[str, Any], source_kind: str) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "case_id": case_id,
        "source_kind": source_kind,
        "log_path": event.get("log_path"),
        "record_id": str(event.get("record_id") or ""),
        "event_id": event.get("event_id"),
        "provider": event.get("provider"),
        "channel": event.get("channel"),
        "computer": event.get("computer"),
        "timestamp": event.get("timestamp"),
        "activity_type": event.get("activity_type"),
        "activity_stage": event.get("activity_stage"),
        "confidence": event.get("confidence"),
        "user_name": event.get("user_name"),
        "user_domain": event.get("user_domain"),
        "user_sid": event.get("user_sid"),
        "logon_id": event.get("logon_id"),
        "process_name": event.get("process_name"),
        "activity_tags": event.get("activity_tags") or [],
        "indicators": event.get("indicators") or [],
        "summary": event.get("summary"),
        "event_data": event.get("event_data") or {},
        "user_data": event.get("user_data") or {},
        "system_data": event.get("system_data") or {},
        "user_context": event.get("user_context") or {},
        "raw_xml": event.get("raw_xml"),
    }


class LogModule:
    """Facade for log metadata and device activity analysis."""

    def extract_file_metadata(self, file_path: str) -> Dict[str, Any]:
        return extract_file_metadata(file_path)

    def parse_event_log(self, log_path: str) -> List[Dict[str, Any]]:
        return parse_event_log(log_path)

    def analyze_event_logs(
        self,
        log_paths: Optional[Sequence[str]] = None,
        limit: int = 100,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return analyze_event_logs(log_paths=log_paths, limit=limit, case_id=case_id)

    def analyze_uploaded_artifact(
        self,
        file_path: str,
        case_id: Optional[str] = None,
        log_paths: Optional[Sequence[str]] = None,
        file_metadata: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        return analyze_uploaded_artifact(
            file_path,
            case_id=case_id,
            log_paths=log_paths,
            file_metadata=file_metadata,
            limit=limit,
        )

    def persist_log_analysis(self, analysis: Dict[str, Any], source_path: Optional[str] = None) -> Dict[str, Any]:
        return persist_log_analysis(analysis, source_path=source_path)