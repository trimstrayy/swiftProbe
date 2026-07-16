from __future__ import annotations

from uuid import uuid4
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

try:
    from backend.core.supabase_db import get_supabase_client
except ImportError:  # pragma: no cover - supports running from the backend folder
    from core.supabase_db import get_supabase_client

try:
    from backend.orchestrator import process_evidence_pipeline
except ImportError:  # pragma: no cover - supports running from the backend folder
    from orchestrator import process_evidence_pipeline

try:
    from backend.modules.log_module import analyze_uploaded_artifact
except ImportError:  # pragma: no cover - supports running from the backend folder
    from modules.log_module import analyze_uploaded_artifact

try:
    from backend.modules.ram_module import analyze_ram_dump, sanity_check_ram_capture
except ImportError:  # pragma: no cover - supports running from the backend folder
    from modules.ram_module import analyze_ram_dump, sanity_check_ram_capture

app = Flask(__name__)
UPLOAD_ROOT = Path("evidence") / "uploads"
RAM_UPLOAD_ROOT = UPLOAD_ROOT / "ram"


def _json_error(message: str, status_code: int = 400):
    return jsonify({"ok": False, "error": message}), status_code


def _get_targets(client):
    if client is None:
        return [], False, "Supabase is not configured"

    try:
        response = (
            client.table("target_artifacts")
            .select("filename,expected_sha256,description")
            .order("filename")
            .execute()
        )
        rows = getattr(response, "data", []) or []
        return rows, True, None
    except Exception as exc:
        return [], True, str(exc)


def _get_recovered(client, case_id: str | None = None):
    if client is None:
        return [], False, "Supabase is not configured"

    try:
        query = client.table("files_recovered").select("*")
        if case_id:
            query = query.eq("case_id", case_id)
        response = query.order("match_found", desc=True).order("filename").execute()
        rows = getattr(response, "data", []) or []
        return rows, True, None
    except Exception as exc:
        return [], True, str(exc)


def _run_pipeline_for_image(image_file: Path, case_id: str):
    from backend.hasher import hash_file

    client = get_supabase_client()
    source_meta = hash_file(str(image_file))
    try:
        log_analysis = analyze_uploaded_artifact(str(image_file), str(case_id), file_metadata=source_meta)
    except Exception as exc:
        log_analysis = {
            "case_id": case_id,
            "artifact_path": str(image_file),
            "error": str(exc),
            "file_metadata": source_meta,
            "event_log_scan": {
                "logs_scanned": [],
                "event_count": 0,
                "usb_connection_events": [],
                "file_transfer_events": [],
                "usb_connection_count": 0,
                "file_transfer_count": 0,
            },
            "uploaded_event_count": 0,
            "uploaded_events": [],
            "summary": {
                "source_filename": source_meta.get("filename"),
                "source_hash": source_meta.get("hash"),
                "source_size_bytes": source_meta.get("size", 0),
                "usb_events_found": 0,
                "file_transfer_events_found": 0,
                "uploaded_log_events_found": 0,
            },
        }
    recovered_before, connected_before, error_before = _get_recovered(client, case_id=case_id)

    processed = process_evidence_pipeline(str(image_file), str(case_id))
    matches = [row for row in processed if row.get("match_found")]

    return {
        "ok": True,
        "case_id": case_id,
        "image_path": str(image_file),
        "source_image_hash": source_meta.get("hash"),
        "source_image_size": source_meta.get("size", 0),
        "file_metadata": source_meta,
        "log_analysis": log_analysis,
        "database_sync_status": "connected" if client is not None else "not_configured",
        "supabase_connected": connected_before,
        "supabase_error": error_before,
        "total_files_carved": len(processed),
        "total_matches_found": len(matches),
        "recovered_files": processed,
        "new_rows_estimate": max(len(processed) - len(recovered_before), 0),
    }


def _save_uploaded_image(uploaded_file, case_id: str) -> Path:
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    case_dir = UPLOAD_ROOT / secure_filename(case_id or "case")
    case_dir.mkdir(parents=True, exist_ok=True)

    original_name = secure_filename(uploaded_file.filename or "uploaded_image.bin")
    stored_name = f"{uuid4().hex}_{original_name}"
    stored_path = case_dir / stored_name
    uploaded_file.save(stored_path)
    return stored_path


def _save_uploaded_ram(uploaded_file, case_id: str) -> Path:
    RAM_UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    case_dir = RAM_UPLOAD_ROOT / secure_filename(case_id or "case")
    case_dir.mkdir(parents=True, exist_ok=True)

    original_name = secure_filename(uploaded_file.filename or "uploaded_memory.raw")
    stored_name = f"{uuid4().hex}_{original_name}"
    stored_path = case_dir / stored_name
    uploaded_file.save(stored_path)
    return stored_path


def _resolve_ram_source(payload=None):
    payload = payload or {}
    case_id = payload.get("case_id") or request.form.get("case_id")
    image_path = payload.get("image_path") or request.form.get("image_path")
    uploaded_file = request.files.get("ram_file") or request.files.get("file") or request.files.get("image_file")

    stored_path = None
    if uploaded_file is not None and uploaded_file.filename:
        if not case_id:
            raise ValueError("case_id is required when uploading a RAM capture.")
        stored_path = _save_uploaded_ram(uploaded_file, str(case_id))
        image_path = str(stored_path)

    if not image_path:
        raise ValueError("image_path or ram_file is required.")

    ram_path = Path(str(image_path))
    if not ram_path.exists():
        raise FileNotFoundError(f"RAM image not found: {ram_path}")

    return case_id, ram_path, stored_path


@app.get("/")
def health_check():
    client = get_supabase_client()
    targets, supabase_connected, target_error = _get_targets(client)
    recovered, _, recovered_error = _get_recovered(client)
    return jsonify(
        {
            "ok": True,
            "status": "ok",
            "service": "swiftprobe-backend",
            "supabase_configured": client is not None,
            "supabase_connected": supabase_connected,
            "target_artifacts_count": len(targets),
            "files_recovered_count": len(recovered),
            "target_error": target_error,
            "recovered_error": recovered_error,
        }
    )


@app.get("/api/status")
def api_status():
    return health_check()


@app.get("/api/targets")
def list_targets():
    client = get_supabase_client()
    targets, connected, error = _get_targets(client)
    return jsonify(
        {
            "ok": error is None,
            "supabase_configured": client is not None,
            "supabase_connected": connected,
            "count": len(targets),
            "items": targets,
            "error": error,
        }
    )


@app.get("/api/recovered-files")
def list_recovered_files():
    client = get_supabase_client()
    case_id = request.args.get("case_id")
    recovered, connected, error = _get_recovered(client, case_id=case_id)
    return jsonify(
        {
            "ok": error is None,
            "supabase_configured": client is not None,
            "supabase_connected": connected,
            "case_id": case_id,
            "count": len(recovered),
            "items": recovered,
            "error": error,
        }
    )


@app.post("/api/pipeline/run")
def run_pipeline():
    payload = request.get_json(silent=True) or {}
    image_path = payload.get("image_path")
    case_id = payload.get("case_id")

    if not image_path or not case_id:
        return _json_error("Both image_path and case_id are required.", 400)

    image_file = Path(str(image_path))
    if not image_file.exists():
        return _json_error(f"Evidence image not found: {image_file}", 404)

    try:
        return jsonify(_run_pipeline_for_image(image_file, str(case_id)))
    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "case_id": case_id,
                "image_path": str(image_file),
                "error": str(exc),
            }
        ), 500


@app.post("/api/pipeline/upload")
def run_pipeline_upload():
    case_id = request.form.get("case_id")
    uploaded_file = request.files.get("image_file") or request.files.get("file") or request.files.get("image")

    if not case_id:
        return _json_error("case_id is required.", 400)

    if uploaded_file is None or not uploaded_file.filename:
        return _json_error("An image_file upload is required.", 400)

    try:
        saved_path = _save_uploaded_image(uploaded_file, str(case_id))
        payload = _run_pipeline_for_image(saved_path, str(case_id))
        payload.update(
            {
                "uploaded_filename": uploaded_file.filename,
                "stored_path": str(saved_path),
            }
        )

        return jsonify(payload)
    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "case_id": case_id,
                "error": str(exc),
            }
        ), 500


@app.post("/api/ram/sanity")
def ram_sanity_check():
    payload = request.get_json(silent=True) or {}

    try:
        case_id, ram_path, stored_path = _resolve_ram_source(payload)
        report = sanity_check_ram_capture(str(ram_path))
        return jsonify(
            {
                "ok": True,
                "case_id": case_id,
                "image_path": str(ram_path),
                "stored_path": str(stored_path) if stored_path else None,
                "report": report,
                **report,
            }
        )
    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
            }
        ), 500


@app.post("/api/ram/analyze")
def ram_analyze():
    payload = request.get_json(silent=True) or {}

    try:
        case_id, ram_path, stored_path = _resolve_ram_source(payload)
        analysis = analyze_ram_dump(str(ram_path))
        return jsonify(
            {
                "ok": True,
                "case_id": case_id,
                "image_path": str(ram_path),
                "stored_path": str(stored_path) if stored_path else None,
                **analysis,
            }
        )
    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
            }
        ), 500


@app.get("/supabase")
def supabase_status():
    client = get_supabase_client()
    return jsonify({"ok": True, "supabase_configured": client is not None})


if __name__ == "__main__":
    # NOTE: The reloader (debug=True) spawns a watchdog that monitors the
    # filesystem. Uploading/processing large forensic captures (e.g. a 510MB
    # RAM image) triggers file-write events that can restart the worker
    # mid-request, severing the connection with net::ERR_CONNECTION_RESET
    # instead of returning a clean 500. We therefore run WITHOUT the reloader.
    # Debug is kept off so a Volatility subprocess crash cannot kill the worker
    # and so the dev server behaves closer to a production WSGI server.
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
