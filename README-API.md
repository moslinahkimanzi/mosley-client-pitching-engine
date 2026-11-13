# MCAS — Mosley Client Acquisition System

MCAS is a browser-based prospect research and sales workflow tool for website-development services. It has a FastAPI backend, persistent SQLite workspace storage, and an external JavaScript dashboard.

## Run locally on Ubuntu / Firefox

Use Python 3.12 or later and Node.js 22 for the full test suite.

```bash
git clone https://github.com/moslinahkimanzi/mosley-client-pitching-engine.git
cd mosley-client-pitching-engine
git checkout feature/mcas-research-completion

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

Add your Serper key to `.env` as `SERPER_API_KEY=...` (never paste it into browser code or commit it). For Kenyan Google results, set `SERPER_GL=ke` and `SERPER_HL=en`. Open Firefox at http://127.0.0.1:8000. Create an account on the welcome screen. The API's interactive documentation is at http://127.0.0.1:8000/docs.

## Implemented in this branch

- Premium responsive dark dashboard with overview, prospects, research, email studio, reply assistant, proposals, follow-ups, integrations and security pages.
- Account registration/login/logout, salted PBKDF2 password hashes, random session tokens stored as hashes, HttpOnly session cookies and CSRF protection.
- Per-account filtering for prospects, drafts, follow-ups, proposals and integration tokens.
- Prospect CRUD, evidence notes, source URL, CRM status and do-not-contact flag.
- Rules-based Website Strategy Advisor: recommends a site type, sitemap, useful features, quality standards and an improvement roadmap based on business type, goals, current online presence, budget range and verified notes. Recommendations are starting points and must be validated with the client.
- User-triggered business research through Serper Places, plus Serper web search. Location, business category and optional keyword are searched together. Available public business name, address, category, phone and website details are displayed; listed websites receive a lightweight check. Results are unverified discovery leads, not proof of current business details or buying intent.
- Public website checks include HTTP status, title, mobile viewport metadata, meta description, H1 and form presence. Outbound connections are pinned to validated public IPs; redirects are revalidated; private/reserved IPs and non-standard ports are blocked. This remains a lightweight check, not a full audit.
- Accepted-client workflow: mark a prospect as Won to generate a detailed website-builder prompt using its recorded business category and verified notes.
- Evidence-led template email generation, optional OpenAI-compatible AI provider, reply assistance, proposals and saved drafts.
- Gmail OAuth connection with encrypted refresh-token storage. MCAS creates drafts only; it does not read, search, list or monitor incoming messages and exposes no send endpoint. When Gmail is already connected and research finds a public contact email, a Gmail draft is created automatically; otherwise the draft stays in MCAS for review. Customer replies must be pasted manually into Reply Assistant. Google documents gmail.compose as draft management plus send-capable at API scope level, but this application only calls the drafts.create endpoint.
- Follow-up task tracking, audit events, metrics and JSON workspace export.
- Security headers, Trusted Host validation, basic per-process rate limiting, request-size cap, Docker health check, CI tests and dependency audit workflow.

## Configure optional providers

No external provider key is required to run the core app.

### Live web search
Add your Serper API key as `SERPER_API_KEY` in the server-side `.env` file. MCAS uses Serper Places for local business discovery and Serper Search for web search. Optional `SERPER_GL` and `SERPER_HL` values select a Google result region and language (for example, `ke` and `en`). Never put the API key in `assets/app.js` or browser code. Check Serper's current quota and terms in your account.

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

Set the output as `MCAS_ENCRYPTION_KEY`. Enable Gmail API for the Google project. The only scope requested is `https://www.googleapis.com/auth/gmail.compose`. MCAS does not request `gmail.readonly`, `gmail.modify`, `gmail.metadata`, or `https://mail.google.com/`; it does not read incoming messages and has no send operation. Important: Google's `gmail.compose` scope itself is capable of managing drafts and sending mail at API-permission level. MCAS uses it only for the Gmail `users.drafts.create` method. Review this permission trade-off before connecting a business Gmail account.

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

Other boundaries: MCAS is not a whole-internet crawler. Serper results can be incomplete, stale or unavailable. Missing website URLs do not prove a business has no website. It does not harvest private contacts. It never sends outreach or follow-ups. It does not read incoming Gmail messages; customer replies must be supplied manually. Automated proposals and emails are rules-based templates unless you explicitly use the separately configured AI assistant, which may incur provider charges. Website checks are lightweight technical observations, not full SEO, accessibility or security audits.

Never commit `.env`, OAuth credentials, encryption keys, database files or customer exports.


## Research accuracy and prioritisation (completion branch)

The Research Command Centre sends the entered location, business category and optional keyword to Serper Places. If Places returns no records, MCAS falls back to Serper web search and treats those links as unverified sources, not confirmed business websites. Results are cached in process for five minutes to reduce repeated provider requests.

Each research result includes an explainable opportunity-priority score (0–100) and the signals that contributed to it. The score ranks research work; it does not represent buying intent, prove a business lacks a website, or replace human verification. The score is stored in the prospect CRM score field.

For business websites returned by Serper Places, the result displays limited HTTP/title/mobile viewport/meta description/H1/form observations available to MCAS. This is not a full performance, SEO, accessibility, security, or conversion audit. Search coverage depends on Serper results and the configured account quota. MCAS does not claim to crawl the entire internet.