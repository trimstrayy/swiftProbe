"""Basic smoke tests for VERDICT: SwiftProbe.

Run with:
    cd /Users/umangarayamajhi/code/swiftProbe
    .venv/bin/python -m pytest tests/test_smoke.py -v
"""
import sys
import os
import hashlib
import tempfile
from pathlib import Path

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestAppImports:
    """Verify all critical modules import without errors."""

    def test_flask_app_imports(self):
        from backend.app import app
        routes = {r.rule for r in app.url_map.iter_rules()}
        required = {
            "/api/status", "/api/targets", "/api/recovered-files",
            "/api/pipeline/run", "/api/pipeline/upload",
            "/api/ram/sanity", "/api/ram/analyze",
            "/api/log/analyze", "/api/report/generate",
            "/api/report/generate-download",
        }
        assert required.issubset(routes), f"Missing routes: {required - routes}"

    def test_hasher_module(self):
        from backend.hasher import hash_file, hash_bytes, normalize_sha256
        assert normalize_sha256(" ABC ") == "abc"
        assert hash_bytes(b"test") == hashlib.sha256(b"test").hexdigest()

    def test_hasher_hash_file(self):
        from backend.hasher import hash_file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"Hello World")
            f.flush()
            path = f.name
        try:
            meta = hash_file(path)
        finally:
            os.unlink(path)
        assert "hash" in meta
        assert len(meta["hash"]) == 64
        assert meta["size"] == 11
        assert meta["filename"] == os.path.basename(path)

    def test_orchestrator_imports(self):
        from backend.orchestrator import process_evidence_pipeline
        assert callable(process_evidence_pipeline)

    def test_supabase_db_imports(self):
        from backend.core.supabase_db import get_supabase_client, get_supabase_config
        assert callable(get_supabase_client)
        url, key = get_supabase_config()

    def test_report_generator_imports(self):
        from backend.reports.generator import generate_pdf, build_report_data
        assert callable(generate_pdf)
        assert callable(build_report_data)

    def test_ram_module_imports(self):
        from backend.modules.ram_module import analyze_ram_dump, sanity_check_ram_capture
        assert callable(analyze_ram_dump)
        assert callable(sanity_check_ram_capture)

    def test_disk_module_imports(self):
        from backend.modules.disk_module import scan_disk_image
        assert callable(scan_disk_image)

    def test_log_module_imports(self):
        from backend.modules.log_module import analyze_uploaded_artifact
        assert callable(analyze_uploaded_artifact)


class TestCarver:
    """Verify the file carver works on test data."""

    def test_carver_imports(self):
        from modules.carver import carve_from_image
        assert callable(carve_from_image)

    def test_carver_detects_jpg(self):
        """Create a valid JPEG >= 512 bytes and verify the carver finds it."""
        from modules.carver import carve_from_image

        jpg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        jpg_data += b"\xff\xdb\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08"
        jpg_data += b"\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d"
        jpg_data += b"\xfe" * 600
        jpg_data += b"\xff\xd9"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(jpg_data)
            img_path = f.name

        try:
            outdir = tempfile.mkdtemp()
            results = carve_from_image(img_path, outdir, min_size=0)
            assert len(results) >= 1, "Carver should find at least one JPG"
            jpg_results = [r for r in results if r["type"] == "jpg"]
            assert len(jpg_results) >= 1
            assert os.path.exists(jpg_results[0]["path"])
        finally:
            os.unlink(img_path)
            import shutil
            shutil.rmtree(outdir, ignore_errors=True)

    def test_carver_detects_pdf(self):
        """Create a valid PDF >= 512 bytes and verify the carver finds it."""
        from modules.carver import carve_from_image

        pdf_body = b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        pdf_body += b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        pdf_body += b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
        pdf_body += b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n"
        pdf_body += b"0000000058 00000 n \n0000000115 00000 n \n"
        pdf_body += b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n"
        pdf_body += b"x" * 600
        pdf_data = b"%PDF-1.4\n" + pdf_body + b"%%EOF"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(pdf_data)
            img_path = f.name

        try:
            outdir = tempfile.mkdtemp()
            results = carve_from_image(img_path, outdir, min_size=0)
            pdf_results = [r for r in results if r["type"] == "pdf"]
            assert len(pdf_results) >= 1, "Carver should find at least one PDF"
        finally:
            os.unlink(img_path)
            import shutil
            shutil.rmtree(outdir, ignore_errors=True)

    def test_is_forensic_image(self):
        from modules.disk_module import is_forensic_image
        raw_path = dd_path = bin_path = txt_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as f:
                f.write(b"test")
                raw_path = f.name
            with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as f:
                f.write(b"test")
                dd_path = f.name
            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
                f.write(b"test")
                bin_path = f.name
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
                f.write(b"test")
                txt_path = f.name
            assert is_forensic_image(raw_path), ".raw should be forensic image"
            assert is_forensic_image(dd_path), ".dd should be forensic image"
            assert is_forensic_image(bin_path), ".bin should be forensic image"
            assert not is_forensic_image(txt_path), ".txt should not be forensic image"
        finally:
            for p in [raw_path, dd_path, bin_path, txt_path]:
                if p and os.path.exists(p):
                    os.unlink(p)


class TestReportGenerator:
    """Verify the report generator produces output."""

    def test_build_report_data(self):
        from backend.reports.generator import build_report_data
        case_meta = {
            "case_number": "TEST-001",
            "investigator_name": "Test Examiner",
            "organization": "Test Lab",
        }
        data = build_report_data(case_meta)
        assert data["case"]["case_number"] == "TEST-001"
        assert data["case"]["investigator_name"] == "Test Examiner"
        assert not data["is_blank"]
        assert len(data["chain_of_custody"]) > 0
        assert len(data["module_summary"]) == 4

    def test_generate_pdf_html_fallback(self):
        """PDF generation should fall back to HTML gracefully."""
        from backend.reports.generator import generate_pdf
        case_meta = {
            "case_number": "TEST-001",
            "investigator_name": "Test Examiner",
            "credentials": "GCFA",
            "organization": "Test Lab",
            "target_machine": "DESKTOP-TEST",
            "asset_id": "AST-001",
        }
        result = generate_pdf(case_meta=case_meta)
        assert result is not None
        assert os.path.exists(result)
        if result.endswith(".html"):
            content = Path(result).read_text(encoding="utf-8")
            assert "TEST-001" in content
            assert "Report of Examination" in content


class TestHashIntegrity:
    """Verify SHA-256 consistency across the pipeline."""

    def test_hash_bytes_vs_file(self):
        from backend.hasher import hash_bytes, hash_file
        content = b"Forensic test data for integrity verification"
        expected = hashlib.sha256(content).hexdigest()
        assert hash_bytes(content) == expected

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            path = f.name
        try:
            meta = hash_file(path)
            assert meta["hash"] == expected
        finally:
            os.unlink(path)

    def test_normalize_sha256(self):
        from backend.hasher import normalize_sha256
        assert normalize_sha256("  ABC123  ") == "abc123"
        assert normalize_sha256(None) == ""
        assert normalize_sha256("") == ""


class TestFlaskAPI:
    """Verify Flask API routes respond correctly."""

    def test_health_endpoint(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/status")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert data["status"] == "ok"
            assert data["service"] == "swiftprobe-backend"

    def test_targets_endpoint(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/targets")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "ok" in data
            assert "items" in data

    def test_recovered_files_endpoint(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/recovered-files")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "ok" in data

    def test_generate_report_endpoint(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.post(
                "/api/report/generate-download",
                json={
                    "case_meta": {
                        "case_number": "TEST-001",
                        "investigator_name": "Test Examiner",
                        "credentials": "GCFA",
                        "organization": "Test Lab",
                        "target_machine": "DESKTOP-TEST",
                        "asset_id": "AST-001",
                    }
                },
            )
            assert resp.status_code in (200, 500)
            if resp.status_code == 200:
                assert resp.mimetype in ("application/pdf", "text/html")

    def test_pipeline_run_missing_params(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.post("/api/pipeline/run", json={})
            assert resp.status_code == 400
            data = resp.get_json()
            assert "error" in data