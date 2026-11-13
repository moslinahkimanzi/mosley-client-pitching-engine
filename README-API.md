# MCAS — Mosley Client Acquisition System

MCAS is a browser-based prospect research and sales workflow tool for website-development services. It has a FastAPI backend, persistent SQLite workspace storage, and an external JavaScript dashboard.

## Run locally on Ubuntu / Firefox

Use Python 3.12 or later and Node.js 22 for the full test suite.

```bash
git clone https://github.com/moslinahkimanzi/mosley-client-pitching-engine.git
cd mosley-client-pitching-engine
git checkout build/production-foundation

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
``

Put the generated value into `MCAS_SECRET_KEY` inside `.env`. Then load local settings and start the server:

```bash
set -a
source .env
set +a
uvicorn backend.app:app --host 127.0.0.1 --port 8000
``

Open Firefox at http://127.0.0.1:8000. Create an account on the welcome screen. The API's interactive documentation is at http://127.0.0.1:8000/docs.

## Implemented in this branch

- Premium responsive dark dashboard with overview, prospects, research, email studio, reply assistant, proposals, follow-ups, integrations and security pages.
- Account registration/login/logout, salted PBKDF2 password hashes, random session tokens stored as hashes, HttpOnly session cookies and CSRF protection.
- Per-account filtering for prospects, drafts, follow-ups, proposals and integration tokens.
- Prospect CRUD, evidence notes, source URL, CRM status and do-not-contact flag.
- Rules-based Website Strategy Advisor: recommends a site type, sitemap, useful features, quality standards and an improvement roadmap based on business type, goals, current online presence, budget range and verified notes. Recommendations are starting points and must be validated with the client.
- Optional Brave Search integration. Results are unverified discovery records and must be checked before outreach.
- Public website quick-check with HTTP status, title and viewport tag. Outbound connections are pinned to validated public IPs; redirects are revalidated; private/reserved IPs and non-standard ports are blocked.
- Evidence-led template email generation, optional OpenAI-compatible AI provider, reply assistance, proposals and saved drafts.
- Gmail OAuth connection with encrypted refresh-token storage and Gmail draft creation only. MCAS does not send messages.
- Follow-up task tracking, audit events, metrics and JSON workspace export.
- Security headers, Trusted Host validation, basic per-process rate limiting, request-size cap, Docker health check, CI tests and dependency audit workflow.

## Configure optional providers

No external provider key is required to run the core app.

### Live web search
For a no-card signup option, create a Serper account and add its API key as `SERPER_API_KEY` on the server. MCAS will use Serper when this key is set. Serper currently advertises 2,500 free queries at signup with no credit card required; check its current terms and quota. Alternatively, set `BRAVE_SEARCH_API_KEY` to use Brave Search (Brave requires payment-card verification). Never put provider keys in `assets/app.js` or browser code. Provider quotas and pricing are controlled by the provider.

### AI writing assistant
Set these server environment variables:
- `AI_API_BASE_URL` — OpenAI-compatible API base URL, e.g. a provider's HTTPS `/v1` base.
- `AI_API_KEY` — provider secret.
- `AI_MODEL` — model identifier accepted by that provider.

This is optional and may create usage costs. Generated content is a draft, not verified evidence.

### Gmail drafts
Create an OAuth client in Google Cloud Console (Web application) and configure the exact redirect URI:
`https://YOUR-HOST/api/integrations/gmail/callback`

Set `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, and `GMAIL_REDIRECT_URI` on the server. Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
``

Set the output as `MCAS_ENCRYPTION_KEY`. Enable Gmail API for the Google project. The scope requested is `gmail.compose`; this integration creates drafts and does not send email.

## Test before publishing

Run the automated suite:

```bash
python -m compileall -q backend tests
python -m unittest discover -s tests -v
node --check assets/app.js
pip-audit -r requirements.txt
``

Follow the step-by-step manual checklist in [TESTING.md](TESTING.md). GitHub Actions repeats compilation, Python API tests, JavaScript syntax checks and package vulnerability auditing on branch pushes and pull requests.

## Production limitations — do not skip this section

This branch is a testable release candidate, **not a security-certified commercial SaaS**.

Before accepting public users or customer data:
1. Move from SQLite to managed PostgreSQL and test database migrations/backups. SQLite is intended for one instance and a persistent disk.
2. Replace the in-process rate limiter with a shared service such as Redis; add account/device-aware throttling and abuse monitoring.
3. Add email verification, password reset, MFA, session/device management and account deletion.
4. Add a production secret manager, HTTPS-only deployment, exact `MCAS_ALLOWED_HOSTS` and `MCAS_ALLOWED_ORIGINS`, persistent encrypted backups, monitoring and alerting.
5. Complete an independent security review / penetration test and resolve all findings.
6. Add real payment-provider checkout, signed webhook verification, subscription lifecycle handling and tax/receipt requirements before enabling paid plans. Billing is intentionally disabled.
7. Add provider-specific live integration tests with credentials in a non-production staging environment.

Other boundaries: there is no whole-internet crawler, no automatic contact harvesting, no automatic email sending, no automatic follow-up sending, and no guarantee that every public business record is complete. Search is provider-backed and optional. Website checks are lightweight technical observations, not full SEO, accessibility or security audits.

Never commit `.env`, OAuth credentials, encryption keys, database files or customer exports.
