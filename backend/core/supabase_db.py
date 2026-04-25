import os

from supabase import create_client

_SUPABASE_CLIENT = None


def get_supabase_client():
    global _SUPABASE_CLIENT

    if _SUPABASE_CLIENT is None:
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")

        if not supabase_url or not supabase_key:
            return None

        _SUPABASE_CLIENT = create_client(supabase_url, supabase_key)

    return _SUPABASE_CLIENT
