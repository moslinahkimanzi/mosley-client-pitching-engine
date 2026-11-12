# MCAS API foundation

This branch adds an independently runnable FastAPI service.

## Run locally (Ubuntu)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set MCAS_SECRET_KEY to a random value before real use.
uvicorn backend.app:app --reload
```
API docs: http://127.0.0.1:8000/docs

## Current API
- Account register/login/logout/current user with HttpOnly session cookie
- User-scoped lead CRUD and draft storage in SQLite
- Audit events for key account/lead/draft actions
- Optional Brave Search adapter (server-side key only)
- Basic public website metadata check with private-network target blocking
- Metrics endpoint

## Important limitations before production
- This is a foundation, not a production security certification.
- Set a strong random MCAS_SECRET_KEY and MCAS_COOKIE_SECURE=true behind HTTPS.
- Configure allowed origins to the exact deployed origin.
- SQLite is for early single-instance use; use managed PostgreSQL for production/multiple instances.
- In-memory rate limiting, CSRF controls, email verification, password reset, MFA, OAuth/Gmail, AI provider adapters, billing and automated tests still need implementation.
- Website checker is intentionally limited and should receive additional DNS-rebinding/redirect protections before exposing it publicly.
- Search API requires a provider account and key; search results must be manually verified.
- No messages are sent automatically; drafts remain pending approval.
