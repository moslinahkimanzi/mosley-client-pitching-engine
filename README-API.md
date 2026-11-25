# MCAS — Mosley Client Acquisition System

MCAS is a browser-based prospect research and sales workflow tool for website-development services. It has a FastAPI backend, persistent SQLite workspace storage, and an external JavaScript dashboard.

## Run locally on Ubuntu / Firefox

Use Python 3.12 or later and Node.js 22 for the full test suite.

```bash
git clone https://github.com/moslinahkimanzi/mosley-client-pitching-engine.git
cd mosley-client-pitching-engine
git checkout release/mcas-prelaunch-2026-11

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

Add your Serper key to `.env` as `SERPER_API_KEY=...` (never paste it into browser code or commit it). The country and language configured under **My workspace** control the Serper `gl` and `hl` parameters for that customer. Open Firefox at http://127.0.0.1:8000. Create an account on the welcome screen. The API's interactive documentation is at http://127.0.0.1:8000/docs.

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

## Evidence-backed prospect research and business verification

The research run uses Serper Places for local business discovery. If the first query returns no local entities, MCAS retries with a simpler category-and-location Places query. It does **not** turn ordinary organic web links into business records.

Every newly discovered record starts as **Unverified**. MCAS stores the provider listing's name, address, category, phone (when supplied), website URL (when supplied), source link, and a limited website response check. Missing fields remain missing; MCAS must not invent email addresses, phone numbers, addresses, official domains or legal identity.

In Prospects, **Recheck business identity** performs a fresh Places lookup and an independent web search. It only marks the record as provider-reconfirmed when the business name matches, the saved phone or address also matches, and at least one non-Google public web result matches the business name and selected market. The evidence panel displays the listing and independent source URLs/snippets. This is corroboration, not an authoritative business-register check or proof that a person controls the phone/email/domain.

A user must review the evidence and select **I reviewed this listing — confirm business** before the record becomes **Verified**. The confirmation action records the human decision, updates the displayed address/phone from the matched public listing, and may check a website candidate only when its domain also appears among the independent sources. A successful HTTP response verifies reachability only, not website ownership or complete functionality.

Proposals and pending outreach drafts are created only after this human confirmation. Drafts remain approval-only; MCAS does not send messages. A failed or ambiguous match remains unverified and can be manually investigated. Recheck before outreach because public listings and contact details can change.

No search provider guarantees complete or fully up-to-date contact details. Legal registration, contact ownership and consent to contact still require appropriate independent confirmation.

## Workspace regional preferences

Each authenticated workspace has independent regional preferences saved in the server database:

- Country / market selection. The selected country is sent as Serper's region parameter for Places and web-search discovery; the city or area still needs to be entered in the Research field.
- Display currency. Indicative website estimates are converted from the MCAS KES planning bands using the ExchangeRate-API Open Access endpoint. The daily response is cached server-side; MCAS shows the source attribution and update timestamp when available. The endpoint requires attribution, allows caching and commercial conversion, and prohibits redistribution of its raw rate table. The displayed conversion is an estimate aid, not an invoice or payment settlement rate.
- Time zone. MCAS detects the browser's IANA time zone during first setup, stores it on the workspace and supports manual overrides. Follow-up input and display use that selected time zone.
- Language. Supported selections are English, Kiswahili, French, Spanish, German, Portuguese and Arabic. AI-generated email, reply and proposal text follows the selected language. The current localization covers the main navigation and the regional-preferences page; other detailed interface text is still primarily English.
- Appearance. Choose dark, light or follow-device theme.
- Regional price adjustment. The workspace can edit its own planning multiplier. The starting website price bands are Kenya-based; for other countries MCAS applies the selected multiplier and explicitly advises validating local supplier rates. They are not verified price surveys for each country.

Preferences belong to the signed-in user/workspace and are not shared between customer accounts. Selecting a country does not automatically make the typed city valid; enter a location that matches the chosen country.

## Configure optional providers

No external provider key is required to run the core app.

### Live web search
Add your Serper API key as `SERPER_API_KEY` in the server-side `.env` file. MCAS uses Serper Places for local business discovery and Serper Search for web search. Optional `SERPER_GL` and `SERPER_HL` values select a Google result region and language (for example, `ke` and `en`). Never put the API key in `assets/app.js` or browser code. Check Serper's current quota and terms in your account.

### AI writing assistant (Google Gemini free tier)

MCAS uses the OpenAI-compatible chat-completions endpoint, so no extra Python SDK is required. To try the AI reply assistant without adding a payment card, create a Gemini API key in [Google AI Studio](https://aistudio.google.com/apikey). Check that your account is eligible and review the current [supported regions](https://ai.google.dev/gemini-api/docs/available-regions) and [pricing / free-tier limits](https://ai.google.dev/gemini-api/docs/pricing). Quotas and available models can change.

Set these values in the private server-side `.env` file:

```dotenv
AI_API_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
AI_API_KEY=YOUR_GEMINI_API_KEY
AI_MODEL=gemini-3.8-flash
```

Keep the key out of GitHub, screenshots, browser code and chat messages. Restart MCAS after changing `.env`. The Integrations page should then show AI as configured. The main Generate AI reply action calls this provider; if the provider is missing or unavailable, MCAS shows an error rather than substituting a fixed reply. Review and edit all output before saving or sending.

Important privacy note: Google's free tier may use submitted content to improve its products. Do not submit passwords, payment details, sensitive personal information, confidential client material or messages you do not have permission to process. Review Google's current terms before using it with real customer communications.

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

This branch is a pre-launch release candidate, **not a security-certified commercial SaaS**. The repository branch is not a production deployment.

Before accepting public users or customer data:
1. **Database:** the current backend is SQLite-only and supports a single app instance on a persistent disk. Migrate to managed PostgreSQL, create tested migrations, verify tenant isolation and complete backup/restore drills before scaling or using multiple app instances.
2. **Shared abuse controls:** the current rate limiter uses the application database. Add a shared Redis-backed limiter, proxy-aware client IP handling, monitoring and alerting before multi-instance deployment.
3. **Identity and recovery:** production disables MCAS password registration/login and uses Google OpenID Connect. The backend verifies the Google token signature, audience, nonce, expiry and `email_verified` claim; password recovery is therefore handled by Google. Administrator tools require TOTP MFA and single-use recovery codes. Customers should secure their Google accounts with MFA; MCAS does not yet provide a separate customer TOTP factor, device management or account deletion.
4. **Secrets and edge security:** use a production secret manager, HTTPS-only deployment, exact `MCAS_ALLOWED_HOSTS` and `MCAS_ALLOWED_ORIGINS`, a trusted proxy configuration, security monitoring and tested encrypted off-site backups.
5. **Independent assurance:** complete an independent security review / penetration test and resolve all findings. A dependency audit and automated tests do not replace this.
6. **Payments:** complete provider sandbox tests, merchant KYC/approval, live credentials, HTTPS webhook delivery, settlement reconciliation, refunds/reversals and tax/receipt requirements before enabling paid plans. Keep `MCAS_BILLING_ENABLED=false`; the payment path is not live.
7. **Staging:** deploy to a separate non-production environment and run provider-specific integration tests with test credentials before any production release.

Other boundaries: MCAS is not a whole-internet crawler. Serper results can be incomplete, stale or unavailable. Missing website URLs do not prove a business has no website. It does not harvest private contacts. It never sends outreach or follow-ups. It does not read incoming Gmail messages; customer replies must be supplied manually. Automated proposals and emails are rules-based templates unless you explicitly use the separately configured AI assistant, which may incur provider charges. Website checks are lightweight technical observations, not full SEO, accessibility or security audits.

Never commit `.env`, OAuth credentials, encryption keys, database files or customer exports.


## Research accuracy and prioritisation (completion branch)

The Research Command Centre sends the entered location, business category and optional keyword to Serper Places. If Places returns no records, MCAS falls back to Serper web search and treats those links as unverified sources, not confirmed business websites. Results are cached in process for five minutes to reduce repeated provider requests.

Each research result includes an explainable opportunity-priority score (0–100) and the signals that contributed to it. The score ranks research work; it does not represent buying intent, prove a business lacks a website, or replace human verification. The score is stored in the prospect CRM score field.

For business websites returned by Serper Places, the result displays limited HTTP/title/mobile viewport/meta description/H1/form observations available to MCAS. This is not a full performance, SEO, accessibility, security, or conversion audit. Search coverage depends on Serper results and the configured account quota. MCAS does not claim to crawl the entire internet.

## Production customer protection

Production requires `MCAS_CUSTOMER_MFA_REQUIRED=true` and a separate stable Fernet key in `MCAS_CUSTOMER_MFA_ENCRYPTION_KEY`. Generate the key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store it only in the production secret manager and keep a protected recovery copy. It must be independent from the administrator MFA encryption key. Production startup fails if the customer MFA requirement or encryption key is missing.

Customers sign in with Google OpenID Connect. MCAS verifies the signed ID token, nonce, audience, validity period and Google's `email_verified` claim. On the first sign-in, a customer receives a limited session that can call only the customer MFA setup/status/verification endpoints. Prospect, report, proposal, billing, integration and other workspace routes remain blocked until TOTP enrollment succeeds. Setup issues ten single-use recovery codes; the session is rotated when enrollment completes. On later sign-ins, customers must enter a current authenticator code or an unused recovery code.

Customers should also enable Google's own account MFA and keep their Google recovery options current. Google remains the account identity and account-recovery provider; MCAS does not store customer Google passwords or implement password-reset emails. If customers lose both their authenticator and every recovery code, an operator-assisted identity re-verification and recovery process is required. Do not edit MFA database columns manually.

## Production administrator setup

1. Configure `MCAS_ADMIN_EMAILS` with the exact Google account email that will administer MCAS. Do not use a shared mailbox.
2. Set `MCAS_ADMIN_MFA_REQUIRED=true` in production. Production startup rejects a false value.
3. Generate a separate stable MFA encryption key with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` and save it as `MCAS_ADMIN_MFA_ENCRYPTION_KEY` in the hosting secret manager. Keep it backed up securely; changing or losing it makes existing authenticator secrets undecryptable.
4. Generate a high-entropy bootstrap value with `python -c "import secrets; print(secrets.token_urlsafe(48))"` and set it as `MCAS_ADMIN_BOOTSTRAP_TOKEN` in the same secret manager. Never put either value in Git, chat or a browser field outside the authenticated enrollment screen.
5. Sign in with the allowlisted Google account, open **Administrator maintenance**, enter the bootstrap value, start setup, add the displayed secret to an authenticator app and verify its current six-digit code.
6. Save all ten recovery codes in a password manager or another secure offline location. They are displayed only once and each can be used one time. Enrollment revokes the current session. Sign in again; the next admin login requires TOTP or an unused recovery code.
7. Once enrollment is confirmed, remove the bootstrap token from the hosting secret manager. Store an offline emergency copy of the encryption key in a separate protected location.

An allowlisted administrator receives unlimited MCAS credits and no subscription/credit-pack charges only after verified Google sign-in and successful MFA enrollment when MFA is required. The server resolves this status from the database user record; it never trusts client-supplied roles or email claims. Admin usage is audit logged. If the administrator loses both their authenticator and all recovery codes, an operator-assisted recovery procedure is required; do not edit the user row casually.

## Release candidate safety notes

- Use `release/mcas-prelaunch-2026-11` as the candidate branch for review; do not deploy it directly to production until the full CI pipeline and the production checklist above pass.
- Billing tests use disposable temporary databases. Do not point automated tests at a production database.
- An administrator receives unlimited usage only when the signed-in server-side user record matches `MCAS_ADMIN_EMAILS`; production additionally requires a linked verified Google identity. Admin usage is written to the audit log. Never trust a role, email or admin flag supplied by the browser.
- Gmail is restricted in application behavior to creating drafts. The Google `gmail.compose` OAuth scope is broader than draft-only at provider permission level, so review that scope warning during Google OAuth verification. MCAS does not request inbox-reading scopes and does not implement a send operation.
- Feedback-driven product improvement is a human-reviewed proposal workflow. It never edits, merges or deploys application code autonomously.
