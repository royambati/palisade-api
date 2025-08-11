import os
from dotenv import load_dotenv

load_dotenv()

# Core
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Database (SQLite dev by default; set to Postgres/Supabase in prod)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./palisade.db")

# API key signup/admin gating for /keys + /admin endpoints
SIGNUP_SECRET = os.getenv("SIGNUP_SECRET")  # if unset, /keys is open (dev mode)

# API key generation
KEY_PREFIX = os.getenv("KEY_PREFIX", "pal_live_")
KEY_BYTES = int(os.getenv("KEY_BYTES", "24"))  # raw token bytes before urlsafe encoding

# Legacy env-based keys (fallback if DB empty or for quick tests)
PALISADE_API_KEYS = [k.strip() for k in os.getenv("PALISADE_API_KEYS", os.getenv("PALISADE_API_KEY", "")).split(",") if k.strip()]

# Rate limit (requests/min per key)
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")