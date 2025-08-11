Palisade — API Keys, Rate Limiting, and Usage Logging

ENV VARS
--------
OPENAI_API_KEY=sk-...
DATABASE_URL=sqlite:///./palisade.db                 # dev; for Postgres/Supabase, set your URI
SIGNUP_SECRET=choose-a-strong-secret                 # required to create/list keys in prod
KEY_PREFIX=pal_live_
KEY_BYTES=24
PALISADE_API_KEYS=                                   # optional legacy keys (comma-separated)
RATE_LIMIT_RPM=60
LOG_LEVEL=INFO

MIGRATION
---------
python migrate.py

RUN (local)
-----------
pip install -r requirements.txt
uvicorn main:app --reload

KEYS
----
# Create a key (admin-gated with SIGNUP_SECRET)
curl -s -X POST "http://localhost:8000/keys" \
  -H "Content-Type: application/json" \
  -H "x-signup-secret: $SIGNUP_SECRET" \
  -d '{"name":"dev@example.com"}'

# Use the key
curl -s -X POST "http://localhost:8000/moderate/text" \
  -H "Content-Type: application/json" \
  -H "x-api-key: pal_live_...yourkey..." \
  -d '{"text":"hello"}' | jq .

# Who am I?
curl -s "http://localhost:8000/keys/me" \
  -H "x-api-key: pal_live_...yourkey..." | jq .

# Revoke myself
curl -s -X DELETE "http://localhost:8000/keys/me" \
  -H "x-api-key: pal_live_...yourkey..." | jq .

ADMIN
-----
# List keys
curl -s "http://localhost:8000/admin/keys" -H "x-signup-secret: $SIGNUP_SECRET" | jq .

# Revoke a key by id
curl -s -X DELETE "http://localhost:8000/admin/keys/42" -H "x-signup-secret: $SIGNUP_SECRET"

NOTES
-----
- Keys are stored hashed with per-key salt; plaintext is shown only once at creation.
- Rate limiting is per-key in-memory for MVP. For multi-instance deployment, move to Redis or a shared store.
- Usage logs store the full moderation result JSON for analytics/billing later.
- Table names are namespaced: palisade_api_keys, palisade_request_logs.