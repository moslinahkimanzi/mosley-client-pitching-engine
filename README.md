# Mosley Client Acquisition System (MCAS)

MCAS is a browser-based prospect research and client-acquisition workspace. It helps a developer discover business prospects, record evidence, assess website opportunities, prepare proposals and draft outreach for human review.

## Current capabilities in this development line
- Authenticated customer workspaces with tenant-scoped prospect and draft data.
- Serper Places / web discovery, with source links and unverified-evidence warnings.
- Website opportunity classification and website strategy recommendations.
- Advanced bounded static website audits covering SEO metadata, mobile hints, accessibility hints, conversion paths, trust signals and selected security response headers.
- Local competitor candidate discovery and limited comparison of publicly listed competitor websites.
- AI-assisted outreach, proposals and manually pasted customer-reply drafting.
- Gmail draft creation only. MCAS does not read/search/monitor inboxes and does not send email.
- Follow-up tasks, customer feedback and governed administrator improvement review.
- Customer email verification for new registrations; authenticator MFA for configured administrators in production.

## Important audit limitations
The website audit does not execute JavaScript, run Lighthouse/Core Web Vitals, verify full WCAG conformance, scan for malware, exploit vulnerabilities or perform penetration testing. Missing headers and metadata are review observations, not proof of exploitable vulnerabilities.

Competitor results are candidate public listings, not verified direct competitors. Search-provider details and ratings can be incomplete or stale. Verify all facts before contacting a business or sharing a report.

No codebase ZIP audit or PDF report export is included in this development line.

## Run locally
1. Clone the repository.
2. Create a virtual environment: `python3 -m venv .venv`
3. Activate it: `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and set a unique local `MCAS_SECRET_KEY`.
6. Start the API and static app:
   ```bash
   set -a && source .env && set +a
   python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
   ```
7. Open `http://127.0.0.1:8000`.

Serper and AI features require server-side API credentials. Never put secrets in browser code or commit `.env`.

## Security
Security is layered and deployment-dependent. Review `SECURITY-OPERATIONS.md` and `SECURITY.md`. Production requires HTTPS, exact trusted origins/hosts, a secrets manager, administrator MFA, protected GitHub branches, encrypted backups and restore tests, WAF/edge request limits, monitoring and independent penetration testing.

Customer MFA and self-service password recovery are not yet implemented. SQLite data-file encryption depends on encrypted hosting storage. The application is not certified or guaranteed secure; do not store sensitive regulated data until the deployment has been independently assessed.

## Development validation
GitHub Actions runs Python compilation, the unit test suite, JavaScript syntax checking and pip-audit dependency checks. Passing CI is not a penetration test or proof of production readiness.
