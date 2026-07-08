import os
from pathlib import Path


def _load_env_file(env_path: Path) -> None:
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

ROOT_DIR = Path(__file__).resolve().parents[2]
if load_dotenv is not None:
    load_dotenv(ROOT_DIR / ".env", override=False)
    load_dotenv(ROOT_DIR / "backend" / ".env", override=False)
else:
    _load_env_file(ROOT_DIR / ".env")
    _load_env_file(ROOT_DIR / "backend" / ".env")

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
