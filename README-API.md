# MCAS API foundation

This branch adds an independently runnable FastAPI service and the first persistent backend layer.

## Run locally (Ubuntu)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
# Put the generated value in MCAS_SECRET_KEY in .env
uvicorn backend.app:app --reload
```
API docs: http://127.0.0.1:8000/docs

## Current API
- Account register/login/logout/current user with HttpOnly session cookie
- User-scoped lead CRUD and draft storage in SQLite
- Audit events for key account/lead/draft actions
- Basic per-process request throttling and Origin validation
- Optional Brave Search adapter (server-side key only)
- Metrics endpoint
- Password hashing with PBKDF2-HMAC-SHA256 and random salts

## Test
```bash
python -m unittest discover -s tests -v
```

## Important limitations before production
- This is a development foundation, not a production security certification.
- The existing `index.html` demo still uses browser localStorage; it is not yet wired to these API endpoints.
- Set a strong random MCAS_SECRET_KEY, MCAS_COOKIE_SECURE=true and MCAS_ENV=production behind HTTPS.
- Configure allowed origins to the exact deployed origin.
- Per-process throttling is not shared between workers; use Redis or equivalent for production.
- SQLite is for early single-instance use; use managed PostgreSQL for production/multiple instances.
- Website audit endpoint is intentionally disabled (501) until DNS-pinned outbound requests and redirect revalidation are implemented. This is a deliberate SSRF safety measure.
- Search API requires a provider account and key; search results are discovery leads, not verified facts.
- CSRF token flow, email verification, password reset, MFA, Gmail OAuth, AI provider adapters, billing, tenant admin tools and automated end-to-end tests remain future work.
- No messages are sent automatically; drafts remain pending approval.
