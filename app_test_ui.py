"""Streamlit-based test UI for SwiftProbe evidence examination.

Run with: `streamlit run app_test_ui.py`

The app supports device file import, chunked hashing, carving, and end-to-end
orchestration against the evidence pipeline.
"""
from __future__ import annotations

import os
import importlib
import sys
from pathlib import Path
from typing import List, Dict

import streamlit as st
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT_DIR / ".env")
except Exception:
    pass

from backend.hasher import hash_file
from backend.core.supabase_db import get_supabase_client
import backend.modules.ram_module as ram_module
from modules.carver import carve_from_image


def fetch_targets(client) -> List[Dict]:
    if client is None:
        return []
    try:
        resp = client.table("target_artifacts").select("filename,expected_sha256,description").execute()
        return getattr(resp, "data", []) or []
    except Exception:
        return []


def save_uploaded_file(uploaded_file) -> Path:
    temp_root = Path("evidence") / "uploads"
    temp_root.mkdir(parents=True, exist_ok=True)
    suffix = Path(uploaded_file.name).suffix or ".bin"
    temp_path = temp_root / f"uploaded_{uploaded_file.name}"
    temp_path.write_bytes(uploaded_file.getbuffer())
    return temp_path


def render_target_fingerprints(client):
    st.subheader("Active Target Fingerprints")
    targets = fetch_targets(client)
    if not targets:
        st.info("No Supabase client configured or no targets available.")
        return []
    st.dataframe(targets, use_container_width=True, hide_index=True)
    return targets


def render_recovered_feed(client, case_id: str):
    st.subheader(f"Recovered Files — Case: {case_id}")
    recovered = fetch_recovered(client, case_id)
    if recovered:
        positives = [r for r in recovered if r.get("match_found")]
        if positives:
            st.error(f"{len(positives)} positive match(es) detected for case {case_id}!")
        st.dataframe(recovered, use_container_width=True, hide_index=True)
    else:
        st.info("No recovered files recorded for this case yet.")
    return recovered


def safe_stage_hash(file_path: Path):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    return hash_file(str(file_path))


def safe_stage_carve(file_path: Path, case_id: str):
    carve_dir = Path("evidence") / "carved_output" / case_id / file_path.stem
    carve_dir.mkdir(parents=True, exist_ok=True)
    return carve_from_image(str(file_path), str(carve_dir))


def safe_stage_orchestrate(file_path: Path, case_id: str):
    from backend.orchestrator import process_evidence_pipeline

    return process_evidence_pipeline(str(file_path), case_id)


def safe_stage_ram(file_path: Path):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    module = importlib.reload(ram_module)
    return module.analyze_ram_dump(str(file_path))


def safe_stage_ram_sanity_check(file_path: Path):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    module = importlib.reload(ram_module)
    sanity_helper = getattr(module, "sanity_check_ram_capture", None)
    if callable(sanity_helper):
        return sanity_helper(str(file_path))
    return module.RAMModule(str(file_path)).sanity_check()


def fetch_recovered(client, case_id: str) -> List[Dict]:
    if client is None:
        return []
    try:
        resp = client.table("files_recovered").select("*").eq("case_id", case_id).order("physical_offset_bytes", {"ascending": True}).execute()
        return getattr(resp, "data", []) or []
    except Exception:
        return []


def main():
    st.set_page_config(page_title="SwiftProbe — Test UI", layout="wide")

    st.sidebar.title("SwiftProbe Test Runner")
    case_id = st.sidebar.text_input("Active Case ID", value="CASE-2026-NIST-01")
    image_path = st.sidebar.text_input("Path to Raw Forensic Image", value="evidence/test_image.raw")
    uploaded_file = st.sidebar.file_uploader(
        "Import forensic file from your device",
        type=["dd", "raw", "img", "bin", "e01"],
    )
    ram_path = st.sidebar.text_input("Path to RAM Capture", value="evidence/test_memory.raw")
    ram_uploaded_file = st.sidebar.file_uploader(
        "Import RAM capture from your device",
        type=["raw", "mem", "dmp", "vmem", "lime", "aff4", "mddramimage"],
    )

    supa = get_supabase_client()
    if supa is None:
        st.sidebar.error("Supabase is not connected")
    else:
        st.sidebar.success("Supabase connected")

    active_file_path = Path(image_path)
    if uploaded_file is not None:
        active_file_path = save_uploaded_file(uploaded_file)
        st.sidebar.success(f"Imported: {uploaded_file.name}")

    st.sidebar.caption(f"Active file: {active_file_path}")

    active_ram_path = Path(ram_path)
    if ram_uploaded_file is not None:
        active_ram_path = save_uploaded_file(ram_uploaded_file)
        st.sidebar.success(f"Imported RAM capture: {ram_uploaded_file.name}")

    st.sidebar.caption(f"Active RAM capture: {active_ram_path}")

    tab_hash, tab_carve, tab_orchestrate, tab_ram = st.tabs(["Hashing", "File Carving", "Orchestration", "RAM Analysis"])

    with tab_hash:
        left, right = st.columns([1, 1])
        with left:
            st.subheader("Evidence Hashing")
            st.write("Apply chunked SHA-256 to the selected file before any extraction.")
            if st.button("Calculate SHA-256", key="hash_only"):
                try:
                    with st.spinner("Hashing evidence..."):
                        if not active_file_path.exists():
                            raise FileNotFoundError(f"File not found: {active_file_path}")
                        meta = safe_stage_hash(active_file_path)
                        st.success("Hash computed successfully")
                        st.json(meta)
                except Exception as exc:
                    st.exception(exc)
        with right:
            render_target_fingerprints(supa)

    with tab_carve:
        left, right = st.columns([1, 1])
        with left:
            st.subheader("File Carving")
            st.write("Run the signature-based carver on the selected evidence file.")
            if st.button("Run Carver", key="carve_only"):
                try:
                    with st.spinner("Carving unallocated sectors..."):
                        if not active_file_path.exists():
                            raise FileNotFoundError(f"File not found: {active_file_path}")
                        carved = safe_stage_carve(active_file_path, case_id)
                        st.success(f"Carver complete — extracted {len(carved)} items")
                        st.dataframe(carved, use_container_width=True, hide_index=True)
                except Exception as exc:
                    st.exception(exc)
        with right:
            render_recovered_feed(supa, case_id)

    with tab_orchestrate:
        st.subheader("Evidence Examination Pipeline")
        st.write("Recommended order: hash the file, carve it, then orchestrate the final matching and insert stage.")

        col_left, col_right = st.columns([1, 1])
        with col_left:
            if st.button("🚀 Execute Full Forensic Pipeline", key="pipeline_full"):
                try:
                    if not active_file_path.exists():
                        raise FileNotFoundError(f"File not found: {active_file_path}")

                    with st.spinner("Processing sectors..."):
                        hash_meta = safe_stage_hash(active_file_path)
                        st.info(f"Pre-hash complete: {hash_meta.get('hash')}")

                        carve_meta = safe_stage_carve(active_file_path, case_id)
                        st.info(f"Carving complete: {len(carve_meta)} items")

                        orch_meta = safe_stage_orchestrate(active_file_path, case_id)
                        st.success(f"Pipeline complete — processed {len(orch_meta)} carved items")

                        positives = [r for r in orch_meta if r.get("match_found")]
                        if positives:
                            st.error(f"{len(positives)} positive match(es) detected in this run")
                            st.dataframe(positives, use_container_width=True, hide_index=True)
                except Exception as exc:
                    st.exception(exc)

        with col_right:
            render_recovered_feed(supa, case_id)

    with tab_ram:
        left, right = st.columns([1, 1])
        with left:
            st.subheader("Volatile Memory Analysis")
            st.write("Run Volatility 3 plugins against a RAM capture to extract process and network artifacts.")
            if st.button("Run RAM Sanity Check", key="ram_sanity_check"):
                try:
                    with st.spinner("Checking RAM capture..."):
                        if not active_ram_path.exists():
                            raise FileNotFoundError(f"File not found: {active_ram_path}")
                        sanity_result = safe_stage_ram_sanity_check(active_ram_path)
                        if sanity_result.get("status") == "pass":
                            st.success("RAM capture looks valid and Volatility parsed it successfully.")
                        else:
                            st.warning("RAM capture does not yet look like a valid memory image.")
                        st.json(sanity_result)
                except Exception as exc:
                    st.exception(exc)
            if st.button("Analyze RAM Capture", key="ram_analysis"):
                try:
                    with st.spinner("Analyzing RAM capture..."):
                        if not active_ram_path.exists():
                            raise FileNotFoundError(f"File not found: {active_ram_path}")
                        ram_result = safe_stage_ram(active_ram_path)
                        st.success("RAM analysis complete")
                        st.json(ram_result.get("summary", {}))
                        warnings = ram_result.get("warnings", [])
                        if warnings:
                            st.warning("RAM analysis completed with a limited network view for this capture.")
                            st.write(
                                "Volatility could not use the network plugins on this image because it appears to be an older Windows XP-era capture. "
                                "The process and process-tree results are still valid, but network connections could not be recovered."
                            )
                        st.subheader("Process List")
                        st.dataframe(ram_result.get("processes", []), use_container_width=True, hide_index=True)
                        st.subheader("Process Tree")
                        st.dataframe(ram_result.get("process_tree", []), use_container_width=True, hide_index=True)
                        st.subheader("Network Connections")
                        st.dataframe(ram_result.get("network_connections", []), use_container_width=True, hide_index=True)
                        if ram_result.get("network_backend"):
                            st.caption(f"Network backend used: {ram_result.get('network_backend')}")
                except Exception as exc:
                    st.exception(exc)
        with right:
            st.subheader("RAM Input Notes")
            st.info("Use a volatile memory image such as .raw, .mem, .dmp, .vmem, .lime, .aff4, or .mddramimage.")
            if active_ram_path.exists():
                st.write(f"Selected RAM capture: {active_ram_path}")
            else:
                st.warning("No RAM capture selected or the path does not exist.")


if __name__ == "__main__":
    main()
