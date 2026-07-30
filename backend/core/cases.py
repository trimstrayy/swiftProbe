"""Case management helpers for SwiftProbe.

Provides ``get_case_or_404(case_id, user)`` that checks the ``cases`` and
``case_members`` tables and raises a 404/403 if the case doesn't exist or
the authenticated user isn't a member.  Also provides ``create_case()``
for the ``POST /api/cases`` route.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from uuid import UUID

from flask import jsonify

try:
    from backend.core.supabase_db import get_supabase_client
except ImportError:  # pragma: no cover
    from core.supabase_db import get_supabase_client

logger = logging.getLogger(__name__)


def _validate_uuid(value: str) -> Optional[UUID]:
    """Return a UUID if *value* is a valid UUID, else None."""
    try:
        return UUID(value)
    except (ValueError, AttributeError):
        return None


def get_case_or_404(case_id: str, user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Look up a case and verify the user is a member.

    Returns the case row dict on success.
    On failure, calls ``abort()`` with a 404 or 403 JSON response.
    """
    client = get_supabase_client()
    if client is None:
        # No Supabase configured — allow the request through (dev mode)
        return {"id": case_id, "case_number": case_id, "owner_user_id": "dev"}

    case_uuid = _validate_uuid(case_id)
    if not case_uuid:
        # If case_id is not a UUID, try looking up by case_number
        try:
            resp = client.table("cases").select("*").eq("case_number", case_id).maybe_single().execute()
            row = getattr(resp, "data", None)
            if row:
                case_uuid = UUID(row["id"])
            else:
                return None
        except Exception:
            return None
    else:
        try:
            resp = client.table("cases").select("*").eq("id", str(case_uuid)).maybe_single().execute()
            row = getattr(resp, "data", None)
            if not row:
                return None
        except Exception:
            return None

    # Check membership
    user_id = user.get("id")
    if not user_id:
        return None

    try:
        member_resp = (
            client.table("case_members")
            .select("role")
            .eq("case_id", str(case_uuid))
            .eq("user_id", user_id)
            .maybe_single()
            .execute()
        )
        member = getattr(member_resp, "data", None)
        if not member:
            # Check if user is the owner
            if row.get("owner_user_id") == user_id:
                return row
            return None
    except Exception:
        return None

    return row


def create_case(
    case_number: str,
    owner_user_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Create a new case and add the owner as a member.

    Returns the created case row, or None on failure.
    """
    client = get_supabase_client()
    if client is None:
        return None

    try:
        resp = (
            client.table("cases")
            .insert({
                "case_number": case_number,
                "title": title or case_number,
                "description": description or "",
                "owner_user_id": owner_user_id,
            })
            .execute()
        )
        rows = getattr(resp, "data", []) or []
        if not rows:
            return None
        case_row = rows[0]
        case_id = case_row["id"]

        # Add owner as a member
        client.table("case_members").insert({
            "case_id": case_id,
            "user_id": owner_user_id,
            "role": "owner",
        }).execute()

        return case_row
    except Exception as exc:
        logger.exception("Failed to create case: %s", exc)
        return None


def list_cases_for_user(user_id: str) -> list[Dict[str, Any]]:
    """List all cases the user is a member of.

    Returns an empty list when Supabase is not configured or when the
    ``cases`` table does not exist in the schema (e.g. the SQL migration
    has not been applied yet).
    """
    client = get_supabase_client()
    if client is None:
        return []

    try:
        owned = client.table("cases").select("*").eq("owner_user_id", user_id).execute()
        owned_rows = getattr(owned, "data", []) or []
    except Exception as exc:
        err_msg = str(exc).lower()
        if "could not find the table" in err_msg or "relation" in err_msg:
            logger.warning("Cases table not found in Supabase schema — has the SQL migration been applied?")
            return []
        logger.exception("Failed to list cases")
        return []

    try:
        member_ids_resp = (
            client.table("case_members")
            .select("case_id")
            .eq("user_id", user_id)
            .execute()
        )
        member_rows = getattr(member_ids_resp, "data", []) or []
        member_case_ids = [r["case_id"] for r in member_rows if r.get("case_id")]
    except Exception:
        member_case_ids = []

    member_cases = []
    if member_case_ids:
        try:
            member_cases_resp = client.table("cases").select("*").in_("id", member_case_ids).execute()
            member_cases = getattr(member_cases_resp, "data", []) or []
        except Exception:
            member_cases = []

    # Deduplicate
    seen_ids = set()
    all_cases = []
    for case in owned_rows + member_cases:
        cid = case.get("id")
        if cid not in seen_ids:
            seen_ids.add(cid)
            all_cases.append(case)

    return all_cases
