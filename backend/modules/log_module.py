"""Windows artifact analysis helpers for SwiftProbe.

This module performs best-effort forensic analysis for Windows event logs,
registry hives, prefetch files, and browser history databases. It extracts
file metadata, reconstructs a master timeline, classifies USB, clipboard, and
file transfer activity, attempts user attribution from common event fields,
and can persist complete analysis runs to Supabase.
"""
from __future__ import annotations

import logging
import json
import mimetypes
import os
import re
import shutil
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from backend.hasher import hash_file, normalize_sha256
except ImportError:  # pragma: no cover - supports running from the backend folder
    from hasher import hash_file, normalize_sha256

try:
    from backend.core.supabase_db import get_supabase_client
except ImportError:  # pragma: no cover - supports running from the backend folder
    from core.supabase_db import get_supabase_client

logger = logging.getLogger(__name__)


WINDOWS_DEFAULT_LOG_PATHS = (
    "System32/winevt/Logs/System.evtx",
    "System32/winevt/Logs/Security.evtx",
    "System32/winevt/Logs/Application.evtx",
    "System32/winevt/Logs/Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
    "System32/winevt/Logs/Microsoft-Windows-UserPnp%4DeviceInstall.evtx",
    "System32/winevt/Logs/Microsoft-Windows-USB-USBHUB3%4Operational.evtx",
    "System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx",
    "System32/winevt/Logs/Microsoft-Windows-User Profile Service%4Operational.evtx",
)

WINDOWS_DEFAULT_ARTIFACT_PATHS = WINDOWS_DEFAULT_LOG_PATHS

REGISTRY_HIVE_NAMES = {
    "ntuser.dat",
    "usrclass.dat",
    "system",
    "software",
    "sam",
    "security",
    "default",
}

REGISTRY_HINT_KEYS = (
    r"software\microsoft\windows\currentversion\explorer\runmru",
    r"software\microsoft\windows\currentversion\explorer\typedpaths",
    r"software\microsoft\windows\currentversion\explorer\typedurls",
    r"software\microsoft\windows\currentversion\explorer\recentdocs",
    r"software\microsoft\windows\currentversion\explorer\comdlg32",
    r"controlset",
    r"usbstor",
    r"mounteddevices",
    r"usb",
)

PREFETCH_EXTENSIONS = {".pf"}

BROWSER_HISTORY_NAMES = {
    "history",
    "places.sqlite",
    "webcachev01.dat",
    "webcachev24.dat",
    "history.db",
    "history.sqlite",
    "visited links.db",
    "visitedlinks",
}

BROWSER_HISTORY_EXTENSIONS = {".sqlite", ".db", ".sqlite3"}

CLIPBOARD_KEYWORDS = (
    "clipboard",
    "copy",
    "copied",
    "paste",
    "pasted",
    "cut",
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
    "download",
    "upload",
    "clipboard",
    "paste",
    "pasted",
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
    2001,
    2003,
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

# --- Logon / session tracing -------------------------------------------------
# Windows Security log event IDs relevant to interactive/RDP logon sessions.
LOGON_SUCCESS_EVENT_ID = 4624
LOGOFF_EVENT_IDS = {4634, 4647}
LOGON_EVENT_IDS = {LOGON_SUCCESS_EVENT_ID, *LOGOFF_EVENT_IDS}

# LogonType 2 = Interactive (physical console), 10 = RemoteInteractive (RDP).
# These are the only logon types considered "physical/interactive" for
# accountability purposes; other logon types (service, batch, network, etc.)
# are noisy and not attributable to a person sitting at the machine.
INTERACTIVE_LOGON_TYPES = {"2", "10"}
LOGON_TYPE_LABELS = {
    "2": "Interactive (console)",
    "10": "RemoteInteractive (RDP)",
}

# Fallback source used when Security.evtx is cleared/unavailable.
PROFILE_SERVICE_CHANNEL_HINT = "user profile service"
PROFILE_LOAD_EVENT_ID = 2
PROFILE_UNLOAD_EVENT_ID = 4


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

    # --- Logon / logoff classification (Security.evtx 4624/4634/4647, and the
    # User Profile Service fallback channel 2/4) is evaluated first since it's
    # a precise, event-ID-driven signal rather than a keyword heuristic.
    event_data = event.get("event_data") or {}
    logon_type = event_data.get("LogonType")
    is_security_channel = "security" in str(event.get("channel") or "").lower()
    is_profile_service_channel = PROFILE_SERVICE_CHANNEL_HINT in str(event.get("channel") or "").lower() or (
        "user profile service" in provider
    )

    if event_id == LOGON_SUCCESS_EVENT_ID and is_security_channel:
        if logon_type in INTERACTIVE_LOGON_TYPES:
            tags.append("session")
            indicators.append(f"event_id:{event_id}")
            indicators.append(f"logon_type:{logon_type}")
            activity_type = "logon_success"
            activity_stage = "logon"
            confidence = 0.95
        else:
            # Non-interactive logon (service/network/batch/etc). Still tagged
            # as observed so it doesn't get mis-picked-up elsewhere, but not
            # treated as an interactive session start.
            tags.append("logon_noninteractive")
            indicators.append(f"event_id:{event_id}")
            indicators.append(f"logon_type:{logon_type}")
            activity_type = "logon_noninteractive"
            activity_stage = "logon"
            confidence = 0.4
    elif event_id in LOGOFF_EVENT_IDS and is_security_channel:
        tags.append("session")
        indicators.append(f"event_id:{event_id}")
        activity_type = "logoff"
        activity_stage = "logoff"
        confidence = 0.9
    elif is_profile_service_channel and event_id == PROFILE_LOAD_EVENT_ID:
        tags.append("session")
        indicators.append(f"event_id:{event_id}")
        indicators.append("source:profile_service_fallback")
        activity_type = "profile_load"
        activity_stage = "logon"
        confidence = 0.7
    elif is_profile_service_channel and event_id == PROFILE_UNLOAD_EVENT_ID:
        tags.append("session")
        indicators.append(f"event_id:{event_id}")
        indicators.append("source:profile_service_fallback")
        activity_type = "profile_unload"
        activity_stage = "logoff"
        confidence = 0.7

    # ── USB event detection ────────────────────────────────────────────────
    # Track whether this event is a USB event so we can skip file_transfer
    # keyword matching below — USB provider names (e.g. "driverframeworks-usermode")
    # or USB event IDs can coincidentally match TRANSFER_KEYWORDS, causing
    # false file_transfer tags on legitimate USB events.
    _is_usb = False

    if provider and any(hint in provider for hint in USB_PROVIDER_HINTS):
        tags.append("usb")
        indicators.append(f"provider:{provider}")
        confidence = max(confidence, 0.65)
        _is_usb = True

    if event_id in USB_EVENT_IDS:
        tags.append("usb")
        indicators.append(f"event_id:{event_id}")
        confidence = max(confidence, 0.9)
        _is_usb = True

    if any(keyword in text for keyword in USB_KEYWORDS):
        tags.append("usb")
        indicators.append("keyword:usb")
        confidence = max(confidence, 0.75)

    if any(keyword in text for keyword in CLIPBOARD_KEYWORDS):
        tags.append("clipboard")
        indicators.append("keyword:clipboard")
        confidence = max(confidence, 0.7)

    # ── File-transfer keyword matching ─────────────────────────────────────
    # Skip TRANSFER_KEYWORDS and FILE_EVENT_IDS checks for events already
    # identified as USB (via provider or event ID) to prevent false
    # file_transfer tags on legitimate USB events. USB events should ONLY
    # be classified as USB, not as file_transfer.
    if not _is_usb:
        if any(keyword in text for keyword in TRANSFER_KEYWORDS):
            tags.append("file_transfer")
            indicators.append("keyword:transfer")
            confidence = max(confidence, 0.7)

        if event_id in FILE_EVENT_IDS:
            tags.append("file_transfer")
            indicators.append(f"event_id:{event_id}")
            confidence = max(confidence, 0.82)

    for field in ("ObjectName", "TargetFilename", "SourceFilename", "DestinationFilename", "FileName", "ShareName", "DeviceName"):
        if event_data.get(field):
            indicators.append(f"field:{field}")
            if field in {"ObjectName", "TargetFilename", "SourceFilename", "DestinationFilename", "FileName"} and not _is_usb:
                tags.append("file_transfer")

    if event_data.get("UserName") or event_data.get("SubjectUserName") or event_data.get("TargetUserName"):
        tags.append("user_attributed")
        indicators.append("field:user")
        confidence = max(confidence, 0.8)

    # USB connection/mount/removal staging is only inferred from keywords when
    # the event hasn't already been classified as a logon/logoff/session event
    # above, so a Security-log logon event never gets overwritten by an
    # incidental keyword match (e.g. "device" appearing in an unrelated field).
    if activity_type == "log_event":
        # Check if it was identified as a USB event via provider, event ID, or tags
        if _is_usb or "usb" in tags or event_id in USB_EVENT_IDS:
            if "mounted" in text or "volume" in text or "drive letter" in text:
                activity_type = "usb_mounted"
                activity_stage = "mounted"
            elif "eject" in text or "remove" in text or "disconnect" in text or "unplug" in text:
                activity_type = "usb_removed"
                activity_stage = "removed"
            else:
                activity_type = "usb_connected"
                activity_stage = "connected"
            confidence = max(confidence, 0.95)
            if "usb" not in tags:
                tags.append("usb")
        elif any(token in text for token in ("completed", "success", "finished")) and "file_transfer" in tags:
            activity_type = "file_transfer_completed"
            activity_stage = "completed"
            confidence = max(confidence, 0.85)
        elif "file_transfer" in tags:
            activity_type = "file_transfer_initiated"
            activity_stage = "initiated"
            confidence = max(confidence, 0.8)
        elif "clipboard" in tags and any(token in text for token in ("paste", "pasted")):
            activity_type = "clipboard_paste"
            activity_stage = "observed"
            confidence = max(confidence, 0.8)
        elif "clipboard" in tags and any(token in text for token in ("copy", "copied", "cut")):
            activity_type = "clipboard_copy"
            activity_stage = "observed"
            confidence = max(confidence, 0.8)


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


def _iter_default_artifact_paths() -> List[str]:
    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    return [str(windows_root / path) for path in WINDOWS_DEFAULT_ARTIFACT_PATHS if (windows_root / path).exists()]


def _is_registry_hive(path: Path) -> bool:
    lower_name = path.name.lower()
    return lower_name in REGISTRY_HIVE_NAMES or lower_name.endswith(".hive") or lower_name.endswith(".reg")


def _is_prefetch_file(path: Path) -> bool:
    return path.suffix.lower() in PREFETCH_EXTENSIONS


def _is_browser_history_file(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name in BROWSER_HISTORY_NAMES:
        return True
    if lower_name.endswith("history") or lower_name.endswith("history.db") or lower_name.endswith("history.sqlite"):
        return True
    return path.suffix.lower() in BROWSER_HISTORY_EXTENSIONS and (
        "history" in lower_name or "places" in lower_name or "webcache" in lower_name
    )


def _artifact_source_kind(path: Path) -> str:
    if path.suffix.lower() in {".evtx", ".xml"}:
        return "event_log"
    if _is_registry_hive(path):
        return "registry_hive"
    if _is_prefetch_file(path):
        return "prefetch"
    if _is_browser_history_file(path):
        return "browser_history"
    return "unknown"


def _read_binary(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read()


def _extract_strings_from_bytes(data: bytes, minimum_length: int = 4) -> List[str]:
    ascii_matches = re.findall(rb"[ -~]{%d,}" % minimum_length, data)
    utf16_matches = re.findall((rb"(?:[ -~]\x00){%d,}" % minimum_length), data)

    results = [match.decode("ascii", errors="ignore").strip() for match in ascii_matches]
    for match in utf16_matches:
        try:
            results.append(match.decode("utf-16le", errors="ignore").strip())
        except Exception:
            continue

    unique_results: List[str] = []
    seen = set()
    for value in results:
        cleaned = value.strip("\x00\t\r\n ")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique_results.append(cleaned)
    return unique_results


def _temp_copy_for_sqlite(path: Path) -> Path:
    temp_handle = tempfile.NamedTemporaryFile(prefix="swiftprobe_history_", suffix=path.suffix, delete=False)
    temp_handle.close()
    shutil.copy2(path, temp_handle.name)
    return Path(temp_handle.name)


def _chrome_time_to_iso(value: Optional[int]) -> Optional[str]:
    if not value:
        return None
    try:
        from datetime import datetime, timedelta, timezone

        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))).isoformat()
    except Exception:
        return None


def _unix_time_to_iso(value: Optional[int]) -> Optional[str]:
    if not value:
        return None
    try:
        from datetime import datetime, timezone

        if value > 10**15:
            value = int(value / 1000000)
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except Exception:
        return None


def _registry_value_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return repr(value)
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_registry_value_to_text(item) for item in value if item is not None)
    return str(value)


def prefetched_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except Exception:
        return 0


def _registry_extract_records(hive_path: Path) -> List[Dict[str, Any]]:
    try:
        from Registry import Registry
    except Exception:
        return []

    try:
        registry = Registry.Registry(str(hive_path))
    except Exception:
        return []

    records: List[Dict[str, Any]] = []

    def walk(key) -> None:
        try:
            key_name = key.path().lower()
        except Exception:
            key_name = ""

        if key_name:
            try:
                values = {value.name(): _registry_value_to_text(value.value()) for value in key.values()}
            except Exception:
                values = {}

            if any(hint in key_name for hint in REGISTRY_HINT_KEYS):
                activity_type = "registry_activity"
                activity_stage = "observed"
                if "usbstor" in key_name or "mounteddevices" in key_name:
                    activity_type = "usb_plugin_detected"
                    activity_stage = "detected"
                elif "runmru" in key_name or "typedpaths" in key_name or "typedurls" in key_name:
                    activity_type = "user_activity"
                elif "recentdocs" in key_name or "comdlg32" in key_name:
                    activity_type = "file_access_activity"

                records.append(
                    {
                        "log_path": str(hive_path),
                        "source_kind": "registry_hive",
                        "record_index": len(records),
                        "event_id": None,
                        "record_id": None,
                        "provider": "registry",
                        "channel": None,
                        "computer": None,
                        "level": None,
                        "task": None,
                        "opcode": None,
                        "keywords": None,
                        "timestamp": None,
                        "user_context": {
                            "user_name": None,
                            "user_domain": None,
                            "user_sid": None,
                            "logon_id": None,
                            "process_name": None,
                            "user_summary": None,
                        },
                        "user_name": None,
                        "user_domain": None,
                        "user_sid": None,
                        "logon_id": None,
                        "process_name": None,
                        "activity_type": activity_type,
                        "activity_stage": activity_stage,
                        "activity_tags": ["registry", activity_type],
                        "confidence": 0.7,
                        "indicators": [f"key:{key_name}"] + [f"value:{name}" for name in values.keys()],
                        "summary": f"Registry artifact: {key_name}",
                        "event_data": values,
                        "user_data": {},
                        "system_data": {"key_path": key_name, "value_count": len(values)},
                        "raw_xml": None,
                    }
                )

        try:
            for child in key.subkeys():
                walk(child)
        except Exception:
            return

    try:
        walk(registry.root())
    except Exception:
        return []

    return records


def _prefetch_extract_records(prefetch_path: Path) -> List[Dict[str, Any]]:
    try:
        data = _read_binary(prefetch_path)
    except Exception:
        return []

    strings = _extract_strings_from_bytes(data)
    signature = data[:4].decode("ascii", errors="ignore") if len(data) >= 4 else None
    version = int.from_bytes(data[4:8], "little") if len(data) >= 8 else None
    executable_name = None
    for value in strings:
        lower_value = value.lower()
        if lower_value.endswith(".exe") or lower_value.endswith(".dll") or lower_value.endswith(".bat") or lower_value.endswith(".ps1"):
            executable_name = Path(value).name
            break

    if executable_name is None and strings:
        executable_name = Path(strings[0]).name

    summary = f"Prefetch artifact: {executable_name or prefetch_path.name}"
    indicators = ["artifact:prefetch", f"strings:{min(len(strings), 20)}"]
    if executable_name:
        indicators.append(f"executable:{executable_name}")

    return [
        {
            "log_path": str(prefetch_path),
            "source_kind": "prefetch",
            "record_index": 0,
            "event_id": None,
            "record_id": None,
            "provider": "prefetch",
            "channel": None,
            "computer": None,
            "level": None,
            "task": None,
            "opcode": None,
            "keywords": None,
            "timestamp": None,
            "user_context": {
                "user_name": None,
                "user_domain": None,
                "user_sid": None,
                "logon_id": None,
                "process_name": executable_name,
                "user_summary": None,
            },
            "user_name": None,
            "user_domain": None,
            "user_sid": None,
            "logon_id": None,
            "process_name": executable_name,
            "activity_type": "prefetch_execution",
            "activity_stage": "observed",
            "activity_tags": ["prefetch", "execution"],
            "confidence": 0.55,
            "indicators": indicators,
            "summary": summary,
            "event_data": {
                "strings_preview": strings[:25],
                "strings_count": len(strings),
                "executable_name": executable_name,
                "signature": signature,
                "version": version,
            },
            "user_data": {},
            "system_data": {
                "file_size": prefetched_size(prefetch_path),
                "suffix": prefetch_path.suffix.lower(),
                "signature": signature,
                "version": version,
            },
            "raw_xml": None,
        }
    ]


def _browser_history_extract_records(history_path: Path) -> List[Dict[str, Any]]:
    temp_path = _temp_copy_for_sqlite(history_path)
    records: List[Dict[str, Any]] = []

    try:
        connection = sqlite3.connect(f"file:{temp_path.as_posix()}?mode=ro", uri=True)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return []

    try:
        cursor = connection.cursor()
        tables = {row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        try:
            if "urls" in tables:
                for row in cursor.execute(
                    "SELECT url, title, visit_count, typed_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
                ):
                    url, title, visit_count, typed_count, last_visit_time = row
                    records.append(
                        {
                            "log_path": str(history_path),
                            "source_kind": "browser_history",
                            "record_index": len(records),
                            "event_id": None,
                            "record_id": None,
                            "provider": "browser_history",
                            "channel": None,
                            "computer": None,
                            "level": None,
                            "task": None,
                            "opcode": None,
                            "keywords": None,
                            "timestamp": _chrome_time_to_iso(last_visit_time),
                            "user_context": {
                                "user_name": None,
                                "user_domain": None,
                                "user_sid": None,
                                "logon_id": None,
                                "process_name": None,
                                "user_summary": None,
                            },
                            "user_name": None,
                            "user_domain": None,
                            "user_sid": None,
                            "logon_id": None,
                            "process_name": None,
                            "activity_type": "browser_history_visit",
                            "activity_stage": "observed",
                            "activity_tags": ["browser_history", "visit"],
                            "confidence": 0.6,
                            "indicators": [f"url:{url}", f"typed_count:{typed_count}", f"visit_count:{visit_count}"],
                            "summary": f"Browser visit: {title or url}",
                            "event_data": {
                                "url": url,
                                "title": title,
                                "visit_count": visit_count,
                                "typed_count": typed_count,
                            },
                            "user_data": {},
                            "system_data": {"table": "urls"},
                            "raw_xml": None,
                        }
                    )
        except Exception:
            pass

        try:
            if "downloads" in tables:
                for row in cursor.execute(
                    "SELECT tab_url, target_path, start_time, end_time, total_bytes, received_bytes, state FROM downloads ORDER BY end_time DESC LIMIT 500"
                ):
                    tab_url, target_path, start_time, end_time, total_bytes, received_bytes, state = row
                    complete = bool(end_time)
                    activity_type = "file_transfer_completed" if complete else "file_transfer_initiated"
                    activity_stage = "completed" if complete else "initiated"
                    records.append(
                        {
                            "log_path": str(history_path),
                            "source_kind": "browser_history",
                            "record_index": len(records),
                            "event_id": None,
                            "record_id": None,
                            "provider": "browser_downloads",
                            "channel": None,
                            "computer": None,
                            "level": None,
                            "task": None,
                            "opcode": None,
                            "keywords": None,
                            "timestamp": _chrome_time_to_iso(end_time or start_time),
                            "user_context": {
                                "user_name": None,
                                "user_domain": None,
                                "user_sid": None,
                                "logon_id": None,
                                "process_name": None,
                                "user_summary": None,
                            },
                            "user_name": None,
                            "user_domain": None,
                            "user_sid": None,
                            "logon_id": None,
                            "process_name": None,
                            "activity_type": activity_type,
                            "activity_stage": activity_stage,
                            "activity_tags": ["browser_history", "download", "file_transfer"],
                            "confidence": 0.75,
                            "indicators": [f"url:{tab_url}", f"target:{target_path}", f"state:{state}"],
                            "summary": f"Browser download {activity_stage}: {Path(target_path).name if target_path else tab_url}",
                            "event_data": {
                                "tab_url": tab_url,
                                "target_path": target_path,
                                "start_time": _chrome_time_to_iso(start_time),
                                "end_time": _chrome_time_to_iso(end_time),
                                "total_bytes": total_bytes,
                                "received_bytes": received_bytes,
                                "state": state,
                            },
                            "user_data": {},
                            "system_data": {"table": "downloads"},
                            "raw_xml": None,
                        }
                    )
        except Exception:
            pass

        try:
            if {"moz_places", "moz_historyvisits"}.issubset(tables):
                for row in cursor.execute(
                    "SELECT moz_places.url, moz_places.title, moz_places.visit_count, moz_historyvisits.visit_date, moz_historyvisits.visit_type "
                    "FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id "
                    "ORDER BY moz_historyvisits.visit_date DESC LIMIT 500"
                ):
                    url, title, visit_count, visit_date, visit_type = row
                    records.append(
                        {
                            "log_path": str(history_path),
                            "source_kind": "browser_history",
                            "record_index": len(records),
                            "event_id": None,
                            "record_id": None,
                            "provider": "firefox_history",
                            "channel": None,
                            "computer": None,
                            "level": None,
                            "task": None,
                            "opcode": None,
                            "keywords": None,
                            "timestamp": _unix_time_to_iso(visit_date),
                            "user_context": {
                                "user_name": None,
                                "user_domain": None,
                                "user_sid": None,
                                "logon_id": None,
                                "process_name": None,
                                "user_summary": None,
                            },
                            "user_name": None,
                            "user_domain": None,
                            "user_sid": None,
                            "logon_id": None,
                            "process_name": None,
                            "activity_type": "browser_history_visit",
                            "activity_stage": "observed",
                            "activity_tags": ["browser_history", "visit"],
                            "confidence": 0.6,
                            "indicators": [f"url:{url}", f"visit_type:{visit_type}", f"visit_count:{visit_count}"],
                            "summary": f"Browser visit: {title or url}",
                            "event_data": {
                                "url": url,
                                "title": title,
                                "visit_count": visit_count,
                                "visit_type": visit_type,
                            },
                            "user_data": {},
                            "system_data": {"table": "moz_places"},
                            "raw_xml": None,
                        }
                    )
        except Exception:
            pass
    finally:
        try:
            connection.close()
        except Exception:
            pass
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass

    return records


def parse_registry_hive(hive_path: str) -> List[Dict[str, Any]]:
    path = Path(hive_path)
    if not path.exists():
        raise FileNotFoundError(f"Registry hive not found: {hive_path}")
    return _registry_extract_records(path)


def parse_prefetch_file(prefetch_path: str) -> List[Dict[str, Any]]:
    path = Path(prefetch_path)
    if not path.exists():
        raise FileNotFoundError(f"Prefetch file not found: {prefetch_path}")
    return _prefetch_extract_records(path)


def parse_browser_history_db(history_path: str) -> List[Dict[str, Any]]:
    path = Path(history_path)
    if not path.exists():
        raise FileNotFoundError(f"Browser history database not found: {history_path}")
    return _browser_history_extract_records(path)


def parse_artifact_file(artifact_path: str) -> List[Dict[str, Any]]:
    path = Path(artifact_path)
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    source_kind = _artifact_source_kind(path)
    if source_kind == "event_log":
        return parse_event_log(artifact_path)
    if source_kind == "registry_hive":
        return parse_registry_hive(artifact_path)
    if source_kind == "prefetch":
        return parse_prefetch_file(artifact_path)
    if source_kind == "browser_history":
        return parse_browser_history_db(artifact_path)
    return []


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
        paths_to_scan = [path]
        if path.is_dir():
            paths_to_scan = [child for child in path.rglob("*") if child.is_file() and _artifact_source_kind(child) != "unknown"]

        for candidate in paths_to_scan:
            scanned_paths.append(str(candidate))
            try:
                raw_events = parse_artifact_file(str(candidate))
            except Exception:
                raw_events = []

            for index, raw_event in enumerate(raw_events):
                parsed = _normalize_event(raw_event, str(candidate), index, _artifact_source_kind(candidate) or source_kind)
                parsed_logs.append(parsed)

    parsed_logs.sort(key=_event_sort_key)
    return parsed_logs, scanned_paths


# --- Logon session parsing / correlation ------------------------------------

def _parse_iso_timestamp(value: Optional[str]):
    """Best-effort parse of an EVTX SystemTime-style ISO string to a datetime.

    Returns None if the value is missing or unparseable; callers must treat a
    None timestamp as "unknown" and not assume ordering against it.
    """
    if not value:
        return None

    from datetime import datetime

    text = str(value).strip()
    # EVTX SystemTime is typically like "2026-01-05T14:32:10.1234567Z".
    # Python's fromisoformat (pre-3.11) can't handle >6 fractional digits or
    # a trailing "Z", so normalize both before parsing.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, _, rest = text.partition(".")
        # rest may look like "1234567+00:00" or "1234567"
        frac = ""
        tz = ""
        for index, char in enumerate(rest):
            if char in "+-" and index > 0:
                frac, tz = rest[:index], rest[index:]
                break
        else:
            frac, tz = rest, ""
        frac = (frac + "000000")[:6]
        text = f"{head}.{frac}{tz}"

    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def parse_logon_sessions(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build interactive logon sessions from already-normalized Security-log events.

    Expects events already produced by `_normalize_event` (i.e. the output of
    `parse_event_log`/`analyze_event_logs`'s internal collection step), so this
    reuses the existing EVTX parsing path rather than re-reading the log file.

    Groups Event ID 4624 (logon success, LogonType 2/10 only) by the target
    Logon ID, then finds the earliest matching 4634/4647 (logoff) for that
    same Logon ID to build a [logon_time, logoff_time] session window.
    """
    logon_events = [event for event in events if event.get("activity_type") == "logon_success"]
    logoff_events = [event for event in events if event.get("activity_type") == "logoff"]

    # Index logoffs by Logon ID for O(1) lookup; a given Logon ID should only
    # log off once, but keep a list in case of duplicate/noisy entries and
    # take the earliest by timestamp.
    logoffs_by_logon_id: Dict[str, List[Dict[str, Any]]] = {}
    for event in logoff_events:
        logon_id = (event.get("event_data") or {}).get("TargetLogonId") or event.get("logon_id")
        if not logon_id:
            continue
        logoffs_by_logon_id.setdefault(str(logon_id), []).append(event)

    sessions: List[Dict[str, Any]] = []
    for event in logon_events:
        event_data = event.get("event_data") or {}
        logon_id = event_data.get("TargetLogonId") or event.get("logon_id")
        if not logon_id:
            # Without a Logon ID we can't correlate this session to anything
            # later, so skip it rather than emit a session we can't close out.
            continue
        logon_id = str(logon_id)

        matching_logoffs = sorted(
            logoffs_by_logon_id.get(logon_id, []),
            key=lambda logoff_event: str(logoff_event.get("timestamp") or ""),
        )
        logoff_event = matching_logoffs[0] if matching_logoffs else None

        logon_type = event_data.get("LogonType")
        sessions.append(
            {
                "logon_id": logon_id,
                "user_name": event.get("user_name"),
                "user_domain": event.get("user_domain"),
                "user_summary": (event.get("user_context") or {}).get("user_summary"),
                "logon_type": logon_type,
                "logon_type_label": LOGON_TYPE_LABELS.get(str(logon_type), f"Type {logon_type}"),
                "logon_time": event.get("timestamp"),
                "logoff_time": logoff_event.get("timestamp") if logoff_event else None,
                "logon_event_id": event.get("event_id"),
                "logoff_event_id": logoff_event.get("event_id") if logoff_event else None,
                "source": "security_log",
                "logon_record_id": event.get("record_id"),
                "logoff_record_id": logoff_event.get("record_id") if logoff_event else None,
                "attributed_usb_event_indicators": [],
            }
        )

    return sessions


def parse_profile_service_fallback(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build best-effort sessions from the User Profile Service fallback channel.

    Used only when the Security log is cleared/unavailable and no
    `parse_logon_sessions` results were produced. This channel doesn't carry a
    Logon ID, so sessions are correlated by user + nearest following unload
    event rather than a shared session identifier. Attribution confidence for
    fallback sessions is intentionally lower and callers should label these
    distinctly from Security-log-derived sessions.
    """
    load_events = [event for event in events if event.get("activity_type") == "profile_load"]
    unload_events = sorted(
        (event for event in events if event.get("activity_type") == "profile_unload"),
        key=lambda event: str(event.get("timestamp") or ""),
    )

    sessions: List[Dict[str, Any]] = []
    consumed_unload_indices: set = set()

    for load_event in load_events:
        user_summary = (load_event.get("user_context") or {}).get("user_summary")
        load_time = str(load_event.get("timestamp") or "")

        matched_unload = None
        matched_index = None
        for index, unload_event in enumerate(unload_events):
            if index in consumed_unload_indices:
                continue
            unload_user_summary = (unload_event.get("user_context") or {}).get("user_summary")
            unload_time = str(unload_event.get("timestamp") or "")
            if unload_user_summary == user_summary and unload_time >= load_time:
                matched_unload = unload_event
                matched_index = index
                break

        if matched_index is not None:
            consumed_unload_indices.add(matched_index)

        sessions.append(
            {
                "logon_id": None,
                "user_name": load_event.get("user_name"),
                "user_domain": load_event.get("user_domain"),
                "user_summary": user_summary,
                "logon_type": None,
                "logon_type_label": "Unknown (profile service fallback)",
                "logon_time": load_event.get("timestamp"),
                "logoff_time": matched_unload.get("timestamp") if matched_unload else None,
                "logon_event_id": load_event.get("event_id"),
                "logoff_event_id": matched_unload.get("event_id") if matched_unload else None,
                "source": "profile_service_fallback",
                "logon_record_id": load_event.get("record_id"),
                "logoff_record_id": matched_unload.get("record_id") if matched_unload else None,
                "attributed_usb_event_indicators": [],
            }
        )

    return sessions


def correlate_usb_events_with_sessions(
    usb_events: Sequence[Dict[str, Any]], sessions: Sequence[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Attach attributed-user info to USB events whose timestamp falls within a session window.

    Returns (attributed_usb_events, updated_sessions). USB events are copied
    (not mutated in place) before annotation. A session with no logoff_time is
    treated as still-open, i.e. it covers everything from logon_time onward,
    since we have no evidence the session ended.
    """
    parsed_sessions = []
    for session in sessions:
        logon_dt = _parse_iso_timestamp(session.get("logon_time"))
        logoff_dt = _parse_iso_timestamp(session.get("logoff_time"))
        parsed_sessions.append((session, logon_dt, logoff_dt))

    attributed_usb_events: List[Dict[str, Any]] = []
    for usb_event in usb_events:
        usb_dt = _parse_iso_timestamp(usb_event.get("timestamp"))
        annotated = dict(usb_event)
        annotated["attributed_user_summary"] = None
        annotated["attributed_logon_id"] = None
        annotated["attributed_session_source"] = None

        if usb_dt is not None:
            for session, logon_dt, logoff_dt in parsed_sessions:
                if logon_dt is None or usb_dt < logon_dt:
                    continue
                if logoff_dt is not None and usb_dt > logoff_dt:
                    continue
                # Session window matches (or session is still open); attribute
                # this USB event to it.
                annotated["attributed_user_summary"] = session.get("user_summary")
                annotated["attributed_logon_id"] = session.get("logon_id")
                annotated["attributed_session_source"] = session.get("source")
                session["attributed_usb_event_indicators"].append(
                    usb_event.get("record_id") or usb_event.get("indicators") or "usb_event"
                )
                break

        attributed_usb_events.append(annotated)

    return attributed_usb_events, [session for session, _, _ in parsed_sessions]


def analyze_event_logs(
    log_paths: Optional[Sequence[str]] = None,
    limit: int = 100,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect Windows artifacts for USB, clipboard, file-transfer, and user activity."""
    candidate_paths = [str(path) for path in (log_paths or _iter_default_artifact_paths()) if path]
    events, scanned_paths = _collect_events_from_paths(candidate_paths, source_kind="device_scan")

    usb_events = _select_events(events, lambda event: "usb" in (event.get("activity_tags") or []))
    file_transfer_events = _select_events(events, lambda event: "file_transfer" in (event.get("activity_tags") or []))
    clipboard_events = _select_events(events, lambda event: "clipboard" in (event.get("activity_tags") or []))
    user_attribution_events = _select_events(events, lambda event: bool(event.get("user_context", {}).get("user_summary")))
    usb_connected_events = _select_events(events, lambda event: event.get("activity_type") == "usb_connected")
    usb_mounted_events = _select_events(events, lambda event: event.get("activity_type") == "usb_mounted")
    usb_removed_events = _select_events(events, lambda event: event.get("activity_type") == "usb_removed")
    file_transfer_started_events = _select_events(events, lambda event: event.get("activity_type") == "file_transfer_initiated")
    file_transfer_completed_events = _select_events(events, lambda event: event.get("activity_type") == "file_transfer_completed")
    clipboard_copy_events = _select_events(events, lambda event: event.get("activity_type") == "clipboard_copy")
    clipboard_paste_events = _select_events(events, lambda event: event.get("activity_type") == "clipboard_paste")
    registry_events = _select_events(events, lambda event: event.get("source_kind") == "registry_hive")
    prefetch_events = _select_events(events, lambda event: event.get("source_kind") == "prefetch")
    browser_history_events = _select_events(events, lambda event: event.get("source_kind") == "browser_history")

    # --- Session trace: build sessions from Security.evtx first; fall back to
    # the User Profile Service channel only if no Security-log sessions were
    # found (e.g. the Security log was cleared or is unavailable).
    logon_sessions = parse_logon_sessions(events)
    session_trace_source = "security_log"
    if not logon_sessions:
        logon_sessions = parse_profile_service_fallback(events)
        session_trace_source = "profile_service_fallback" if logon_sessions else "none"

    usb_connected_events, logon_sessions = correlate_usb_events_with_sessions(usb_connected_events, logon_sessions)

    activity_counts = _summarize_activity(events)
    user_counts = _summarize_users(events)
    timeline = events[:limit]

    return {
        "case_id": case_id,
        "logs_scanned": scanned_paths,
        "artifact_types": sorted({str(event.get("source_kind") or "unknown") for event in events}),
        "event_count": len(events),
        "usb_connection_count": len(usb_connected_events),
        "usb_mounted_count": len(usb_mounted_events),
        "usb_removed_count": len(usb_removed_events),
        "file_transfer_started_count": len(file_transfer_started_events),
        "file_transfer_completed_count": len(file_transfer_completed_events),
        "file_transfer_count": len(file_transfer_events),
        "clipboard_count": len(clipboard_events),
        "clipboard_copy_count": len(clipboard_copy_events),
        "clipboard_paste_count": len(clipboard_paste_events),
        "registry_event_count": len(registry_events),
        "prefetch_event_count": len(prefetch_events),
        "browser_history_event_count": len(browser_history_events),
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
        "clipboard_events": clipboard_events[:limit],
        "clipboard_copy_events": clipboard_copy_events[:limit],
        "clipboard_paste_events": clipboard_paste_events[:limit],
        "registry_events": registry_events[:limit],
        "prefetch_events": prefetch_events[:limit],
        "browser_history_events": browser_history_events[:limit],
        "user_attribution_events": user_attribution_events[:limit],
        "logon_sessions": logon_sessions[:limit],
        "session_trace_source": session_trace_source,
        "session_count": len(logon_sessions),
        "summary": {
            "event_count": len(events),
            "usb_connection_count": len(usb_connected_events),
            "usb_mounted_count": len(usb_mounted_events),
            "usb_removed_count": len(usb_removed_events),
            "file_transfer_started_count": len(file_transfer_started_events),
            "file_transfer_completed_count": len(file_transfer_completed_events),
            "clipboard_count": len(clipboard_events),
            "clipboard_copy_count": len(clipboard_copy_events),
            "clipboard_paste_count": len(clipboard_paste_events),
            "registry_event_count": len(registry_events),
            "prefetch_event_count": len(prefetch_events),
            "browser_history_event_count": len(browser_history_events),
            "user_attribution_count": len(user_attribution_events),
            "unique_users": len(user_counts),
            "logs_scanned": len(scanned_paths),
            "session_count": len(logon_sessions),
            "session_trace_source": session_trace_source,
        },
    }


def _event_matches_list_key(event: Dict[str, Any], list_key: str) -> bool:
    """Check if a normalized event belongs in the given event-list bucket.
    
    Mirrors the filtering logic used in ``analyze_event_logs`` to select
    events for each list key (e.g. ``usb_connection_events``,
    ``file_transfer_events``).
    """
    tags = event.get("activity_tags") or []
    atype = event.get("activity_type") or ""
    source_kind = event.get("source_kind") or ""
    user_summary = (event.get("user_context") or {}).get("user_summary")

    _LIST_KEY_MAP = {
        "usb_connection_events": lambda: "usb" in tags and atype in ("usb_connected", "usb_activity"),
        "usb_mounted_events": lambda: atype == "usb_mounted",
        "usb_removed_events": lambda: atype == "usb_removed",
        "file_transfer_events": lambda: "file_transfer" in tags,
        "file_transfer_started_events": lambda: atype == "file_transfer_initiated",
        "file_transfer_completed_events": lambda: atype == "file_transfer_completed",
        "clipboard_events": lambda: "clipboard" in tags,
        "clipboard_copy_events": lambda: atype == "clipboard_copy",
        "clipboard_paste_events": lambda: atype == "clipboard_paste",
        "registry_events": lambda: source_kind == "registry_hive",
        "prefetch_events": lambda: source_kind == "prefetch",
        "browser_history_events": lambda: source_kind == "browser_history",
        "user_attribution_events": lambda: bool(user_summary),
    }
    predicate = _LIST_KEY_MAP.get(list_key)
    return predicate() if predicate is not None else False


def _count_uploaded_event_types(events: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    """Count classified event types from a list of normalized events.
    
    Returns counts for USB, file-transfer, clipboard, registry, prefetch,
    browser-history, and user-attribution events.
    """
    return {
        "usb_connection_count": len([e for e in events if "usb" in (e.get("activity_tags") or []) and e.get("activity_type") in ("usb_connected", "usb_activity")]),
        "usb_mounted_count": len([e for e in events if e.get("activity_type") == "usb_mounted"]),
        "usb_removed_count": len([e for e in events if e.get("activity_type") == "usb_removed"]),
        "file_transfer_count": len([e for e in events if "file_transfer" in (e.get("activity_tags") or [])]),
        "file_transfer_started_count": len([e for e in events if e.get("activity_type") == "file_transfer_initiated"]),
        "file_transfer_completed_count": len([e for e in events if e.get("activity_type") == "file_transfer_completed"]),
        "clipboard_count": len([e for e in events if "clipboard" in (e.get("activity_tags") or [])]),
        "clipboard_copy_count": len([e for e in events if e.get("activity_type") == "clipboard_copy"]),
        "clipboard_paste_count": len([e for e in events if e.get("activity_type") == "clipboard_paste"]),
        "registry_event_count": len([e for e in events if e.get("source_kind") == "registry_hive"]),
        "prefetch_event_count": len([e for e in events if e.get("source_kind") == "prefetch"]),
        "browser_history_event_count": len([e for e in events if e.get("source_kind") == "browser_history"]),
        "user_attribution_count": len([e for e in events if bool(e.get("user_context", {}).get("user_summary"))]),
        "event_count": len(events),
    }


def _max_summary(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two summary dicts, taking the maximum value for each numeric key."""
    merged = dict(a)
    for key in b:
        if key in merged and isinstance(merged.get(key), (int, float)) and isinstance(b[key], (int, float)):
            merged[key] = max(merged[key], b[key])
        elif key not in merged:
            merged[key] = b[key]
    return merged


def _event_matches_list_key(event: Dict[str, Any], list_key: str) -> bool:
    """Check if a normalized event matches a specific event list category."""
    atype = str(event.get("activity_type") or "")
    tags = event.get("activity_tags") or []

    if list_key == "usb_connection_events":
        return "usb" in tags or atype.startswith("usb")
    elif list_key == "usb_mounted_events":
        return atype == "usb_mounted" or ("usb" in tags and "mounted" in atype)
    elif list_key == "usb_removed_events":
        return atype == "usb_removed" or ("usb" in tags and ("removed" in atype or "disconnected" in atype))
    elif list_key == "file_transfer_events":
        return "file_transfer" in tags or atype.startswith("file_transfer")
    elif list_key == "file_transfer_started_events":
        return atype == "file_transfer_initiated" or ("file_transfer" in tags and "initiated" in atype)
    elif list_key == "file_transfer_completed_events":
        return atype == "file_transfer_completed" or ("file_transfer" in tags and "completed" in atype)
    elif list_key == "clipboard_events":
        return "clipboard" in tags or atype.startswith("clipboard")
    elif list_key == "clipboard_copy_events":
        return atype == "clipboard_copy"
    elif list_key == "clipboard_paste_events":
        return atype == "clipboard_paste"
    elif list_key == "registry_events":
        return "registry" in tags or atype.startswith("registry")
    elif list_key == "prefetch_events":
        return "prefetch" in tags or atype.startswith("prefetch")
    elif list_key == "browser_history_events":
        return "browser" in tags or atype.startswith("browser")
    elif list_key == "user_attribution_events":
        return bool(event.get("user_context", {}).get("user_summary"))

    return False


def analyze_uploaded_artifact(
    file_path,
    case_id="default_case",
    limit=500,
    file_metadata=None,
    uploaded_events=None,
    merged_summary=None,
    event_log_scan=None,
    merged_event_log_scan=None,
    merged_users=None,
    source_kind="unknown",
):
    if file_metadata is None:
        file_metadata = {}
    if uploaded_events is None:
        uploaded_events = []
    if merged_summary is None:
        merged_summary = {}
    if event_log_scan is None:
        event_log_scan = {}
    if merged_event_log_scan is None:
        merged_event_log_scan = {}
    if merged_users is None:
        merged_users = []

    # 1. Gather all hits from log scan parameters
    scan_usb = merged_event_log_scan.get("usb_connection_hits") or event_log_scan.get("usb_connection_hits") or []
    scan_transfer = merged_event_log_scan.get("file_transfer_hits") or event_log_scan.get("file_transfer_hits") or []

    # 2. Extract hits from uploaded_events (Event ID 2003 = USB, 4663 = File Transfer)
    usb_event_ids = {2003, 2004, 2005, 2100, 2101, 2102, 6416, 1006}
    transfer_event_ids = {4663, 4656, 4670}

    uploaded_usb = []
    uploaded_transfer = []

    for e in uploaded_events:
        e_str = str(e).lower()
        tags = [str(t).lower() for t in e.get("activity_tags", [])]
        act_type = str(e.get("activity_type", "")).lower()
        eid = e.get("event_id") or e.get("EventID")

        if "usb" in act_type or any("usb" in t for t in tags) or eid in usb_event_ids or "driverframeworks-usermode" in e_str:
            uploaded_usb.append(e)

        if "file_transfer" in act_type or any("transfer" in t for t in tags) or eid in transfer_event_ids:
            uploaded_transfer.append(e)

    # 3. Consolidate hit lists
    final_usb_hits = scan_usb if len(scan_usb) >= len(uploaded_usb) else uploaded_usb
    final_transfer_hits = scan_transfer if len(scan_transfer) >= len(uploaded_transfer) else uploaded_transfer

    # 4. Resolve exact counts based on what the UI tables render
    usb_cnt = max(len(final_usb_hits), merged_summary.get("usb_connection_count", 0))
    transfer_cnt = max(len(final_transfer_hits), merged_summary.get("file_transfer_started_count", 0) + merged_summary.get("file_transfer_completed_count", 0))

    # 5. Build summary object containing all frontend key naming variations
    summary_payload = {
        "source_filename": file_metadata.get("filename"),
        "source_hash": file_metadata.get("hash"),
        "source_size_bytes": file_metadata.get("size", 0),
        # USB variations
        "usb_events_found": usb_cnt,
        "usb_connection_count": usb_cnt,
        "usb_matches": usb_cnt,
        "usb_count": usb_cnt,
        # Transfer variations
        "file_transfer_events_found": transfer_cnt,
        "file_transfer_count": transfer_cnt,
        "transfer_matches": transfer_cnt,
        "transfer_count": transfer_cnt,
        # General stats
        "clipboard_events_found": merged_summary.get("clipboard_count", 0),
        "registry_events_found": merged_summary.get("registry_event_count", 0),
        "prefetch_events_found": merged_summary.get("prefetch_event_count", 0),
        "browser_history_events_found": merged_summary.get("browser_history_event_count", 0),
        "user_attributions_found": merged_summary.get("user_attribution_count", 0),
        "uploaded_log_events_found": len(uploaded_events),
        "session_count": event_log_scan.get("summary", {}).get("session_count", 0),
        "session_trace_source": event_log_scan.get("summary", {}).get("session_trace_source", "none"),
    }

    # Ensure nested event_log_scan summary is updated as well
    if isinstance(merged_event_log_scan, dict):
        merged_event_log_scan.setdefault("summary", {}).update(summary_payload)

    return {
        "case_id": case_id,
        "artifact_path": str(Path(file_path).resolve()),
        "artifact_type": source_kind,
        "file_metadata": file_metadata,
        "event_log_scan": merged_event_log_scan,
        "uploaded_event_count": len(uploaded_events),
        "uploaded_events": uploaded_events[:limit],
        # Top-level keys for React state
        "usb_matches": usb_cnt,
        "transfer_matches": transfer_cnt,
        "usb_events_found": usb_cnt,
        "file_transfer_events_found": transfer_cnt,
        "usb_connection_hits": final_usb_hits[:limit],
        "file_transfer_hits": final_transfer_hits[:limit],
        "identified_users": sorted(merged_users),
        "summary": summary_payload,
    }