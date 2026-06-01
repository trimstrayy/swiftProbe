"""Log parsing helpers for SwiftProbe.

Provides a minimal `parse_event_log` function that returns a list of parsed
events. For full functionality, install `python-evtx` and extend the XML
parsing helpers.
"""
from __future__ import annotations

from typing import List, Dict


def parse_event_log(log_path: str) -> List[Dict]:
    """Parse a Windows EVTX file and return a list of event dictionaries.

    This function is intentionally lightweight so it works when `python-evtx`
    is not installed; when available it will produce parsed XML for each
    record.
    """
    try:
        import Evtx
    except Exception:
        # Evtx not installed: return an empty list and allow the caller to
        # fall back to offline conversion tools.
        return []

    events = []
    with Evtx.Evtx(log_path) as evtx:
        for record in evtx.records():
            try:
                xml = record.xml()
                events.append({"xml": xml})
            except Exception:
                continue

    return events
class LogModule:
    pass
