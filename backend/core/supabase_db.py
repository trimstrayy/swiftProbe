import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from supabase import create_client
except Exception:  # pragma: no cover - import availability depends on env
    create_client = None

_SUPABASE_CLIENT = None


def get_supabase_config():
    """Return the first configured Supabase URL/key pair.

    Supports both backend-style names and frontend-style NEXT_PUBLIC names.
    """
    url = (
        os.getenv("NEXT_PUBLIC_SUPABASE_URL")
        or os.getenv("SUPABASE_URL")
    )
    key = (
        os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
        or os.getenv("SUPABASE_SERVICE_KEY")
        or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    )
    return url, key


def get_supabase_client():
    global _SUPABASE_CLIENT

    if _SUPABASE_CLIENT is None:
        if create_client is None:
            return None

        supabase_url, supabase_key = get_supabase_config()

        if not supabase_url or not supabase_key:
            return None

        try:
            _SUPABASE_CLIENT = create_client(supabase_url, supabase_key)
        except Exception:
            return None

    return _SUPABASE_CLIENT
