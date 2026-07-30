"""Tests for authentication and case management modules."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["SWIFTPROBE_TEST_MODE"] = "1"


class TestAuthModule:
    """Verify the JWT auth decorator and helpers."""

    def test_auth_module_imports(self):
        from backend.core.auth import require_auth, optional_auth
        assert callable(require_auth)
        assert callable(optional_auth)

    def test_auth_returns_401_without_token(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/targets")
            assert resp.status_code == 401
            data = resp.get_json()
            assert data.get("error") == "unauthorized"

    def test_auth_accepts_test_token(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/targets", headers={"Authorization": "Bearer test-token"})
            assert resp.status_code == 200

    def test_health_check_no_auth(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/status")
            assert resp.status_code == 200

    def test_auth_rejects_bad_token(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/targets", headers={"Authorization": "Bearer invalid-token"})
            assert resp.status_code == 401


class TestCasesModule:
    """Verify the cases module imports and basic behavior."""

    def test_cases_module_imports(self):
        from backend.core.cases import get_case_or_404, create_case, list_cases_for_user
        assert callable(get_case_or_404)
        assert callable(create_case)
        assert callable(list_cases_for_user)

    def test_cases_endpoints_exist(self):
        from backend.app import app
        routes = {r.rule for r in app.url_map.iter_rules()}
        assert "/api/cases" in routes

    def test_list_cases_requires_auth(self):
        from backend.app import app
        with app.test_client() as client:
            resp = client.get("/api/cases")
            assert resp.status_code == 401