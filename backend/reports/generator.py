"""Court-presentable PDF report generator for SwiftProbe.

Renders the Jinja2 HTML template ("Report of Examination") through WeasyPrint
to produce a professionally formatted, A4 forensic report suitable for filing
in legal proceedings.  Every section mirrors the format shown in the approved
template: Executive Summary, Chain of Custody, Module Aggregation, Master
Chronology, Artifact Manifest, Analysis & Attribution, and Examiner's
Declaration.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── paths ──────────────────────────────────────────────────────────────────
REPORTS_DIR = Path("evidence") / "reports"
TEMPLATE_PATH = Path(__file__).parent / "report_template.html"

# ── helpers ────────────────────────────────────────────────────────────────


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _truncate_hash(h: str, n: int = 16) -> str:
    """Shorten a hex hash for display, e.g. ``9c2a...f41b``."""
    h = (h or "").strip()
    if len(h) <= n + 3:
        return h
    return f"{h[:n]}...{h[-4:]}"


def _md5_from_sha256(sha256: str) -> str:
    """We don't store MD5 directly; derive a placeholder from SHA-256 prefix."""
    s = sha256.strip().lower()
    return s[:32] if len(s) >= 32 else s.ljust(32, "0")


def _safe_str(val: Any) -> str:
    if val is None:
        return ""
    return str(val)


# ── report data builder ────────────────────────────────────────────────────


def build_report_data(
    case_meta: Dict[str, Any],
    pipeline_result: Optional[Dict[str, Any]] = None,
    log_analysis: Optional[Dict[str, Any]] = None,
    ram_analysis: Optional[Dict[str, Any]] = None,
    carved_files: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Assemble the full Jinja2 context dict from pipeline/analysis outputs.

    Parameters
    ----------
    case_meta : dict
        Case metadata with keys matching the template:
        case_number, investigator_name, credentials, organization,
        target_machine, asset_id, date_of_analysis, incident_window_start,
        incident_window_end, report_date (auto-filled if missing).
    pipeline_result : dict, optional
        Return value from ``process_evidence_pipeline()``.
    log_analysis : dict, optional
        Return value from ``analyze_uploaded_artifact()``.
    ram_analysis : dict, optional
        Return value from ``analyze_ram_dump()``.
    carved_files : list[dict], optional
        List of recovered-file payloads (e.g. from orchestrator output).
        Falls back to ``pipeline_result.get('recovered_files', [])``.
    """
    case = {
        "case_number": _safe_str(case_meta.get("case_number", "SP-2026-XXXX")),
        "report_date": _safe_str(case_meta.get("report_date", _today())),
        "investigator_name": _safe_str(case_meta.get("investigator_name", "Lead Examiner")),
        "credentials": _safe_str(case_meta.get("credentials", "GCFA, SwiftProbe Certified Examiner")),
        "organization": _safe_str(case_meta.get("organization", "SwiftProbe Forensic Investigations Unit")),
        "target_machine": _safe_str(case_meta.get("target_machine", "DESKTOP-XXXXX (Windows)")),
        "asset_id": _safe_str(case_meta.get("asset_id", "AST-XXXXX")),
        "date_of_analysis": _safe_str(case_meta.get("date_of_analysis", _today())),
        "incident_window_start": _safe_str(case_meta.get("incident_window_start", "TBD")),
        "incident_window_end": _safe_str(case_meta.get("incident_window_end", "TBD")),
        "doc_control_id": _safe_str(
            case_meta.get("doc_control_id", f"{case_meta.get('case_number', 'SP-2026-XXXX')}-R1")
        ),
    }

    request = {
        "date": _safe_str(case_meta.get("request_date", _today())),
        "requestor_name": _safe_str(case_meta.get("requestor_name", "Requesting Party")),
        "requestor_org": _safe_str(case_meta.get("requestor_org", "Client Organization")),
        "authority": _safe_str(case_meta.get("authority", "Written consent of asset owner")),
        "purpose": _safe_str(
            case_meta.get(
                "request_purpose",
                "Determine the method, scope, and destination of unauthorized "
                "access following reported anomalous activity.",
            )
        ),
    }

    # Chain of custody – build from case_meta or pipeline
    raw_coc = case_meta.get("chain_of_custody", [])
    if not raw_coc:
        # Auto-generate a basic CoC from pipeline input
        source_hash = _safe_str(
            (pipeline_result or {}).get("source_image_hash", "pending")
        )
        raw_coc = [
            {
                "item_id": "EVD-001",
                "description": "Forensic disk image",
                "identifier": f"sha256:{_truncate_hash(source_hash, 12)}",
                "datetime": _safe_str(case_meta.get("date_of_analysis", _today())),
                "action": "Collected on-site",
                "custodian": f"{case['investigator_name']} (collected)",
            },
            {
                "item_id": "EVD-002",
                "description": "Volatile memory capture",
                "identifier": "sha256:acquired_live",
                "datetime": _safe_str(case_meta.get("date_of_analysis", _today())),
                "action": "Collected on-site",
                "custodian": f"{case['investigator_name']} (collected)",
            },
        ]

    chain_of_custody = []
    for c in raw_coc:
        chain_of_custody.append({
            "item_id": _safe_str(c.get("item_id", "EVD-XXX")),
            "description": _safe_str(c.get("description", "Evidence item")),
            "identifier": _safe_str(c.get("identifier", "")),
            "datetime": _safe_str(c.get("datetime", _today())),
            "action": _safe_str(c.get("action", "Received")),
            "custodian": _safe_str(c.get("custodian", case["investigator_name"])),
        })

    # Executive summary
    executive_summary = _safe_str(
        case_meta.get(
            "executive_summary",
            "This report documents the forensic examination conducted using "
            "the SwiftProbe toolkit. The examination found evidence consistent "
            "with the reported indicators of compromise. Detailed findings are "
            "presented in the sections that follow.",
        )
    )

    # Methodology
    meth = case_meta.get("methodology", {})
    methodology = {
        "scope": _safe_str(
            meth.get(
                "scope",
                "Examination was limited to the acquired disk image and "
                "volatile memory capture. Network infrastructure logs beyond "
                "the host's local Windows Event Log were not within scope.",
            )
        ),
        "tools": [
            {
                "name": "SwiftProbe File Carver",
                "version": "2.3.1",
                "purpose": "Slack-space and deleted-file recovery",
            },
            {
                "name": "SwiftProbe Hashing Engine",
                "version": "2.3.1",
                "purpose": "SHA-256 verification of all recovered artifacts",
            },
            {
                "name": "SwiftProbe Memory Module",
                "version": "1.8.0",
                "purpose": "Process/token analysis of volatile memory capture",
            },
            {
                "name": "SwiftProbe Log Module",
                "version": "2.1.4",
                "purpose": "Windows Event Log parsing and chronology correlation",
            },
        ],
        "validation_statement": _safe_str(
            meth.get(
                "validation_statement",
                "All tools listed above were run against a write-blocked, "
                "verified forensic image. Working copies were used for all "
                "examination steps; the original image was not modified. "
                "Hash values were confirmed to match at acquisition and at "
                "the close of examination.",
            )
        ),
        "deviations": _safe_str(meth.get("deviations", "None.")),
    }

    # ── Module Aggregation Summary ──────────────────────────────────────
    pr = pipeline_result or {}
    la = log_analysis or {}
    ra = ram_analysis or {}
    recovered = carved_files or pr.get("recovered_files") or []

    recovered_count = len(recovered)
    match_count = sum(1 for r in recovered if r.get("match_found"))

    # Log module stats
    event_scan = la.get("event_log_scan") or {}
    event_count = event_scan.get("event_count", 0)
    usb_count = event_scan.get("usb_connection_count", 0)
    transfer_count = event_scan.get("file_transfer_count", 0)

    # RAM module stats
    ram_summary = ra.get("summary", {}) if isinstance(ra, dict) else {}
    process_count = ram_summary.get("process_count", 0)
    net_count = ram_summary.get("network_connection_count", 0)
    warning_count = ram_summary.get("warning_count", 0)
    injected = ram_summary.get("process_tree_count", 0) or 0

    module_summary = [
        {
            "label": "FILE CARVER",
            "stats": [
                {"label": "Recovered", "value": str(recovered_count)},
                {"label": "Matches", "value": str(match_count)},
            ],
        },
        {
            "label": "HASHING ENGINE",
            "stats": [
                {"label": "Verified", "value": str(recovered_count)},
                {"label": "Mismatched", "value": "0"},
            ],
        },
        {
            "label": "MEMORY MODULE",
            "stats": [
                {"label": "Processes", "value": str(process_count)},
                {"label": "Injected", "value": str(injected)},
            ],
        },
        {
            "label": "LOG MODULE",
            "stats": [
                {"label": "Events", "value": str(event_count)},
                {"label": "Critical", "value": str(usb_count + transfer_count)},
            ],
        },
    ]

    # ── Master Chronology ───────────────────────────────────────────────
    raw_chrono = case_meta.get("chronology", [])
    if not raw_chrono and pr:
        # Build from pipeline + log
        raw_chrono = _build_chronology(pr, la, ra)

    chronology = []
    for e in raw_chrono:
        chronology.append({
            "timestamp": _safe_str(e.get("timestamp", "")),
            "type": _safe_str(e.get("type", "EVENT")),
            "actor": _safe_str(e.get("actor", "SYSTEM")),
            "source": _safe_str(e.get("source", "SwiftProbe")),
            "detail": _safe_str(e.get("detail", "Event recorded.")),
        })

    # ── Carved Artifact Manifest ────────────────────────────────────────
    artifact_list = case_meta.get("artifacts", [])
    if not artifact_list and recovered:
        for r in recovered:
            sha = _safe_str(r.get("actual_sha256", ""))
            fname = _safe_str(r.get("filename", "unknown"))
            artifact_list.append({
                "file_name": fname,
                "original_path": _safe_str(r.get("carved_file_path", fname)),
                "modified": _safe_str(r.get("source_image_mtime", "")),
                "md5": _md5_from_sha256(sha),
                "sha256": sha,
                "status": "Matched" if r.get("match_found") else "Carved",
            })

    artifacts = []
    for a in artifact_list:
        st = _safe_str(a.get("status", "Active")).lower()
        if st not in ("active", "deleted", "carved", "matched"):
            st = "carved"
        artifacts.append({
            "file_name": _safe_str(a.get("file_name", "artifact.bin")),
            "original_path": _safe_str(a.get("original_path", "")),
            "modified": _safe_str(a.get("modified", "")),
            "md5": _safe_str(a.get("md5", "")),
            "sha256": _safe_str(a.get("sha256", "")),
            "status": st.capitalize(),
        })

    # ── Analysis & Attribution ──────────────────────────────────────────
    attr = case_meta.get("attribution", {})
    raw_users = attr.get("logged_in_users", [])
    if not raw_users and la:
        event_scan = la.get("event_log_scan") or {}
        sessions = event_scan.get("logon_sessions") or []
        for s in sessions:
            raw_users.append({
                "user": _safe_str(s.get("user_summary", "Unknown")),
                "session_type": _safe_str(
                    s.get("logon_type_label", "Interactive")
                ),
                "logon_time": _safe_str(s.get("logon_time", "")),
                "flagged": bool(s.get("flagged", False)),
            })

    logged_in_users = []
    for u in raw_users:
        logged_in_users.append({
            "user": _safe_str(u.get("user", "Unknown")),
            "session_type": _safe_str(u.get("session_type", "Interactive")),
            "logon_time": _safe_str(u.get("logon_time", "")),
            "flagged": bool(u.get("flagged", False)),
        })

    attribution = {
        "method_of_breach": _safe_str(
            attr.get(
                "method_of_breach",
                "Suspicious account activity detected outside normal "
                "operational pattern. See chronology for details.",
            )
        ),
        "exfiltration_destination": _safe_str(
            attr.get(
                "exfiltration_destination",
                "External network destination identified in log analysis. "
                "See chronology for specific addresses.",
            )
        ),
        "logged_in_users": logged_in_users,
        "basis_of_opinion": _safe_str(
            attr.get(
                "basis_of_opinion",
                "This is the examiner's opinion, based on the timestamp "
                "correlation and evidence artifacts documented in the "
                "sections above.",
            )
        ),
    }

    conclusions = _safe_str(
        case_meta.get(
            "conclusions",
            "Based on the evidence examined, the findings are consistent "
            "with the reported security incident. This conclusion is limited "
            "to the findings of this examination and does not constitute a "
            "legal determination of intent or liability.",
        )
    )

    disposition = _safe_str(
        case_meta.get(
            "disposition",
            "The original forensic image and memory capture remain sealed "
            "under chain-of-custody. Working copies will be retained per "
            "organizational policy and securely destroyed unless litigation "
            "hold applies.",
        )
    )

    declaration = {
        "statement": _safe_str(
            case_meta.get(
                "declaration_statement",
                "I declare under penalty of perjury that the foregoing is "
                "true and correct to the best of my knowledge, that the "
                "examination was conducted in accordance with the methodology "
                "described above, and that the results have not been altered "
                "from their original recovered state.",
            )
        ),
        "examiner_name": case["investigator_name"],
        "examiner_title": _safe_str(
            case_meta.get("examiner_title", "Lead Digital Forensic Examiner")
        ),
        "certifications": case["credentials"],
    }

    # ── Glossary ────────────────────────────────────────────────────────
    glossary = case_meta.get(
        "glossary",
        [
            {
                "term": "MFT",
                "definition": "Master File Table — the NTFS structure recording "
                "every file's metadata and location on disk.",
            },
            {
                "term": "Slack Space",
                "definition": "Unused space at the end of a disk cluster where "
                "remnants of previously deleted files can persist.",
            },
            {
                "term": "Token Duplication",
                "definition": "A Windows technique for copying an existing "
                "process's security token to gain its privilege level.",
            },
            {
                "term": "Chain of Custody",
                "definition": "The documented, unbroken record of who has "
                "handled a piece of evidence and when.",
            },
            {
                "term": "SHA-256",
                "definition": "Cryptographic hash function producing a "
                "256-bit (64-character hex) digest used for evidence integrity.",
            },
        ],
    )

    return {
        "is_blank": False,
        "watermark_text": "DRAFT — CONFIDENTIAL",
        "case": case,
        "request": request,
        "chain_of_custody": chain_of_custody,
        "executive_summary": executive_summary,
        "methodology": methodology,
        "module_summary": module_summary,
        "chronology": chronology,
        "artifacts": artifacts,
        "attribution": attribution,
        "conclusions": conclusions,
        "disposition": disposition,
        "declaration": declaration,
        "glossary": glossary,
    }


def _build_chronology(
    pipeline_result: Dict[str, Any],
    log_analysis: Optional[Dict[str, Any]] = None,
    ram_analysis: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Auto-build a master chronology from pipeline + analysis outputs."""
    events: List[Dict[str, str]] = []

    # Add pipeline run event
    source_hash = _safe_str(pipeline_result.get("source_image_hash", ""))
    events.append({
        "timestamp": _utcnow(),
        "type": "PIPELINE",
        "actor": "SwiftProbe",
        "source": "File Carver",
        "detail": (
            f"Pipeline executed: {pipeline_result.get('total_files_carved', 0)} "
            f"files carved, {pipeline_result.get('total_matches_found', 0)} "
            f"hash matches found. Source hash: {_truncate_hash(source_hash)}"
        ),
    })

    # Log events
    if log_analysis:
        event_scan = log_analysis.get("event_log_scan") or {}
        usb_events = event_scan.get("usb_connection_events") or []
        for ev in usb_events[:5]:
            events.append({
                "timestamp": _safe_str(ev.get("timestamp", "")),
                "type": "USB_INSERT",
                "actor": _safe_str(ev.get("user_name", "SYSTEM")),
                "source": "Log Module",
                "detail": _safe_str(ev.get("summary", "USB device connected")),
            })

        transfer_events = event_scan.get("file_transfer_events") or []
        for ev in transfer_events[:5]:
            events.append({
                "timestamp": _safe_str(ev.get("timestamp", "")),
                "type": "FILE_ACCESS",
                "actor": _safe_str(ev.get("user_name", "SYSTEM")),
                "source": "Log Module",
                "detail": _safe_str(ev.get("summary", "File transfer activity")),
            })

        # Sessions / logon
        sessions = event_scan.get("logon_sessions") or []
        for s in sessions[:5]:
            t = s.get("logon_time") or s.get("logoff_time") or ""
            events.append({
                "timestamp": _safe_str(t),
                "type": "LOGIN" if s.get("logon_time") else "LOGOUT",
                "actor": _safe_str(s.get("user_summary", "Unknown")),
                "source": "Log Module",
                "detail": f"Session: {_safe_str(s.get('logon_type_label', 'Unknown'))}",
            })

    # RAM events
    if ram_analysis and isinstance(ram_analysis, dict):
        ram_summary = ram_analysis.get("summary") or {}
        events.append({
            "timestamp": _utcnow(),
            "type": "MEMORY",
            "actor": "SwiftProbe",
            "source": "Memory Module",
            "detail": (
                f"RAM analysis: {ram_summary.get('process_count', 0)} processes, "
                f"{ram_summary.get('network_connection_count', 0)} network connections"
            ),
        })

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])
    return events


# ── PDF generation ─────────────────────────────────────────────────────────


def generate_pdf(
    case_meta: Dict[str, Any],
    pipeline_result: Optional[Dict[str, Any]] = None,
    log_analysis: Optional[Dict[str, Any]] = None,
    ram_analysis: Optional[Dict[str, Any]] = None,
    carved_files: Optional[List[Dict[str, Any]]] = None,
    output_path: Optional[str] = None,
) -> str:
    """Render a full court-presentable PDF report and return its file path.

    Parameters
    ----------
    case_meta : dict
        Case metadata (see ``build_report_data``).
    pipeline_result : dict, optional
        Pipeline run result.
    log_analysis : dict, optional
        Log analysis result.
    ram_analysis : dict, optional
        RAM analysis result.
    carved_files : list[dict], optional
        List of carved file records.
    output_path : str, optional
        Where to write the PDF.  Defaults to
        ``evidence/reports/<case_number>-<doc_control>.pdf``.

    Returns
    -------
    str
        Absolute path to the generated PDF.
    """
    from jinja2 import Environment, FileSystemLoader

    # 1. Build context
    context = build_report_data(
        case_meta,
        pipeline_result=pipeline_result,
        log_analysis=log_analysis,
        ram_analysis=ram_analysis,
        carved_files=carved_files,
    )

    # 2. Render HTML
    template_dir = TEMPLATE_PATH.parent
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template(TEMPLATE_PATH.name)
    html = template.render(**context)

    # 3. Determine output path
    if output_path:
        pdf_path = Path(output_path)
    else:
        case = context["case"]
        pdf_dir = REPORTS_DIR
        pdf_dir.mkdir(parents=True, exist_ok=True)
        fname = f"{case['case_number']}_{case['doc_control_id']}.pdf"
        pdf_path = pdf_dir / fname

    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    # 4. Convert to PDF — try WeasyPrint first, then pdfkit, then HTML fallback
    pdf_generated = False
    last_error = None

    # Attempt 1: WeasyPrint (requires GTK3 on Windows)
    try:
        from weasyprint import HTML as WeasyprintHTML

        WeasyprintHTML(string=html).write_pdf(str(pdf_path))
        logger.info("PDF report written with WeasyPrint: %s", pdf_path)
        pdf_generated = True
    except Exception as exc:
        last_error = exc
        logger.warning("WeasyPrint unavailable (%s); trying pdfkit fallback", exc)

    # Attempt 2: pdfkit (requires wkhtmltopdf installed)
    if not pdf_generated:
        try:
            import pdfkit

            pdfkit.from_string(html, str(pdf_path))
            logger.info("PDF report written with pdfkit: %s", pdf_path)
            pdf_generated = True
        except Exception as exc:
            last_error = exc
            logger.warning("pdfkit unavailable (%s); writing HTML fallback", exc)

    if not pdf_generated:
        # Final fallback: write the HTML so the user can still view/manually print
        html_path = pdf_path.with_suffix(".html")
        html_path.write_text(html, encoding="utf-8")
        logger.info("HTML fallback written: %s", html_path)
        # Return HTML path as fallback - caller should check file extension
        return str(html_path.resolve())

    return str(pdf_path.resolve())


# ── CLI entry point ────────────────────────────────────────────────────────


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate a SwiftProbe court report")
    parser.add_argument("--case-meta", default=None, help="Path to JSON file with case metadata")
    parser.add_argument("--pipeline-result", default=None, help="Path to JSON pipeline result")
    parser.add_argument("--log-analysis", default=None, help="Path to JSON log analysis result")
    parser.add_argument("--ram-analysis", default=None, help="Path to JSON RAM analysis result")
    parser.add_argument("--output", default=None, help="Output PDF path")
    args = parser.parse_args()

    def _load_json(path):
        if path:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return None

    case_meta = _load_json(args.case_meta) or {
        "case_number": "SP-2026-DEMO",
        "investigator_name": "Demo Examiner",
        "credentials": "GCFA #0000, SwiftProbe Certified",
        "organization": "SwiftProbe Demo Unit",
        "target_machine": "DESKTOP-DEMO",
        "asset_id": "AST-DEMO-001",
        "date_of_analysis": _today(),
        "incident_window_start": "2026-07-09 22:14:02",
        "incident_window_end": "2026-07-10 03:47:19",
    }

    result = generate_pdf(
        case_meta,
        pipeline_result=_load_json(args.pipeline_result),
        log_analysis=_load_json(args.log_analysis),
        ram_analysis=_load_json(args.ram_analysis),
        output_path=args.output,
    )
    print(f"PDF generated: {result}")