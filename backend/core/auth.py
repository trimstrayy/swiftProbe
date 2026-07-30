"""Supabase JWT authentication decorator for Flask routes.

Provides `require_auth` which validates a Supabase JWT from the
``Authorization: Bearer <token>`` header.  Token verification uses
PyJWT to decode the JWT and verify its signature using the Supabase
JWT secret.  Unauthenticated requests receive a 401 JSON response.

Test mode
---------
When the environment variable ``SWIFTPROBE_TEST_MODE=1`` is set, the
decorator accepts a special test token ``test-token`` and populates
``g.current_user`` with a fake user.  This allows the existing test
suite to run without a real Supabase instance.
"""

from __future__ import annotations

import functools
import logging
import os
from typing import Any, Callable, Dict, Optional

from flask import g, jsonify, request

try:
    from backend.core.supabase_db import get_supabase_client
except ImportError:  # pragma: no cover
    from core.supabase_db import get_supabase_client

logger = logging.getLogger(__name__)

_TEST_MODE = os.environ.get("SWIFTPROBE_TEST_MODE", "0") == "1"
_TEST_USER = {"id": "test-user-id", "email": "test@swiftprobe.local"}


def _extract_token() -> Optional[str]:
    """Pull the Bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None


def _user_obj_to_dict(user_obj: Any) -> Optional[Dict[str, Any]]:
    """Normalize a Supabase user object/dict into a plain dict.

    ``supabase-py``'s ``auth.get_user()`` returns a response whose
    ``.user`` attribute is a pydantic-style model (it has attributes
    like ``.id``/``.email``, not a ``.get()`` method). Older/alternate
    clients may already hand back a dict. Support both shapes.
    """
    if user_obj is None:
        return None

    # Already a dict (e.g. some client versions / mocks in tests)
    if isinstance(user_obj, dict):
        uid = user_obj.get("id")
        email = user_obj.get("email", "")
    else:
        # Pydantic-style model -> use attribute access
        uid = getattr(user_obj, "id", None)
        email = getattr(user_obj, "email", "") or ""

    if not uid:
        return None
    return {"id": uid, "email": email}


def _verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify a Supabase JWT and return the user dict, or None on failure.

    Tries two approaches in order:
    1. PyJWT decode with the Supabase JWT secret (fast, no network call)
    2. Supabase client ``auth.get_user()`` (fallback, makes a REST call)

    The JWT secret is read from the ``SUPABASE_JWT_SECRET`` or
    ``JWT_SECRET`` environment variable.  If no secret is configured,
    falls back to the Supabase client method.
    """
    # Test mode: accept a well-known test token
    if _TEST_MODE and token == "test-token":
        return dict(_TEST_USER)

    # ── Approach 1: PyJWT decode with JWT secret ──────────────────────
    jwt_secret = os.environ.get("SUPABASE_JWT_SECRET") or os.environ.get("JWT_SECRET")
    if jwt_secret:
        try:
            import jwt

            # Supabase JWTs are signed with HS256 by default
            decoded = jwt.decode(
                token,
                jwt_secret,
                algorithms=["HS256"],
                options={"verify_aud": False},  # Supabase audience varies
            )
            # Extract user info from the JWT payload
            sub = decoded.get("sub", "")
            email = decoded.get("email", "")
            if sub:
                return {"id": sub, "email": email}
            logger.warning("Decoded JWT had no 'sub' claim: %s", decoded)
        except Exception as exc:
            # Log at warning, not debug, so misconfiguration is visible
            logger.warning("PyJWT verification failed, falling back: %s", exc)

    # ── Approach 2: Supabase client auth.get_user() fallback ──────────
    client = get_supabase_client()
    if client is None:
        logger.warning("Supabase client unavailable — rejecting request")
        return None

    try:
        resp = client.auth.get_user(token)
        user = _user_obj_to_dict(getattr(resp, "user", None))
        if user is None:
            logger.warning("Supabase get_user() returned no usable user for token")
        return user
    except Exception as exc:
        logger.warning("Token verification via Supabase client failed: %s", exc)
        return None


def require_auth(fn: Callable) -> Callable:
    """Flask view decorator that enforces Supabase JWT authentication.

    Usage::

        @app.route("/api/sensitive")
        @require_auth
        def sensitive_route():
            return jsonify({"ok": True, "user": g.current_user})
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        token = _extract_token()
        if not token:
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        user = _verify_token(token)
        if user is None:
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def optional_auth(fn: Callable) -> Callable:
    """Flask view decorator that attaches user info if a valid token is present.

    Unlike ``require_auth``, this never returns 401 — it simply sets
    ``g.current_user`` to the authenticated user dict or ``None``.
    Useful for endpoints that behave differently for authenticated
    callers but are still accessible anonymously.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        token = _extract_token()
        user = None
        if token:
            user = _verify_token(token)
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper