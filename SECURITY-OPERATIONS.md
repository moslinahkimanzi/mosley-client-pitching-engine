# MCAS Security Operations Checklist

This checklist separates controls implemented in the repository from controls that must be enabled in hosting, GitHub, identity and backup environments. No system can be guaranteed unhackable.

## Implemented in this code line (pending review and deployment)
- Explicit production `MCAS_ALLOWED_ORIGINS` and `MCAS_ALLOWED_HOSTS`; production startup fails if they are missing or contain local/wildcard hosts.
- CSRF validation and same-origin policy remain enabled.
- SQLite-backed shared fixed-window request limits for processes sharing one database file, plus a per-IP/per-account sign-in throttle. Client IP identifiers are hashed before storage.
- Structured security events for origin/CSRF rejections, rate limits and failed sign-ins; raw IP, email, password, cookies and tokens are not written by these events.
- Additional browser security headers and no-store API responses.
- AI endpoint HTTPS/host validation, with a mandatory `MCAS_AI_ALLOWED_HOSTS` allowlist in production when AI is used.
- AI instructions explicitly classify prospect evidence, search results, external website text and pasted messages as untrusted data.
- Existing ownership checks, CSRF, request-size limits, secure production cookies, SSRF controls and Gmail draft-only boundary are retained.
- GitHub Actions CodeQL scanning for Python and JavaScript/TypeScript, plus weekly Dependabot updates for Python packages and GitHub Actions.

## Required before public production launch
1. **HTTPS and edge protection:** Put the service behind a managed WAF and DDoS protection service. Enable managed OWASP rules, bot protections and request/body limits. The origin server must not be directly reachable from the public internet except through the trusted edge or required health/admin path.
2. **Trusted proxy configuration:** Configure the reverse proxy to overwrite forwarding headers. Do not trust arbitrary `X-Forwarded-For` values. Set trusted proxy IPs only after the hosting topology is known.
3. **MFA and privileged access:** Require passkeys or hardware security keys for GitHub, hosting, DNS, cloud, email and payment-provider administrator accounts. MCAS's current email/password authentication does not yet implement customer MFA or WebAuthn. Use a verified identity provider or complete a separately tested application MFA project before claiming app-level MFA.
4. **GitHub repository controls:** Protect `main`; require pull requests, successful CI and CodeQL checks, block force pushes/deletions, and restrict who can change workflows. Require a review where available. Enable secret scanning and push protection where available. This repository's branch protection is currently disabled and this code change cannot turn it on.
5. **Secrets:** Store production secrets in the host's secret manager, not in Git, image layers or client-side code. Rotate app secrets and API/OAuth keys after any suspected exposure. Restrict secret access to the minimum service identity.
6. **Database and tenant isolation:** Do not expose SQLite or its directory over HTTP. Use encrypted persistent storage for a controlled single-instance deployment. For multiple replicas or higher commercial scale, migrate to managed PostgreSQL with TLS, encryption at rest, least-privilege database roles and row-level tenant policies. Current SQLite encryption-at-rest is provided by the hosting volume, not by the SQLite file itself.
7. **Rate limits:** SQLite counters coordinate workers sharing one database file. For separate containers/replicas or multi-region deployments, move limits to a central Redis/API-gateway limiter with atomic operations. The edge WAF must also enforce global IP and bot limits.
8. **Backups and recovery:** Use a separate backup identity and storage account, encrypted immutable/object-locked backups, independent retention, restore tests and documented recovery objectives. Never keep the only backup on the application host or writable database volume.
9. **Monitoring:** Forward application security logs, WAF events, identity events, database audit events and cloud control-plane logs to a separate protected log service/SIEM. Alert on unusual admin access, repeated sign-in failures, bulk exports, privilege changes, secret access and backup deletion attempts. Current application security events go to the normal server logger and are not tamper-proof by themselves.
10. **Testing:** Run an independent penetration test before taking real customer payments and after material architecture changes. Test account takeover, tenant isolation, IDOR, SSRF/redirects/DNS rebinding, CSRF, prompt injection, secret exposure, abuse limits, recovery and permissions. Use OWASP ASVS 5.0.0 and OWASP LLM application guidance as verification references.

## Production configuration
Set these on the server/secret manager, adapting hostnames to the actual deployment:

```dotenv
MCAS_ENV=production
MCAS_SECRET_KEY=<unique random value at least 40 characters>
MCAS_ALLOWED_ORIGINS=https://your-real-domain.example
MCAS_ALLOWED_HOSTS=your-real-domain.example
MCAS_AI_ALLOWED_HOSTS=api.groq.com
```

For Gemini use `MCAS_AI_ALLOWED_HOSTS=generativelanguage.googleapis.com`. Do not use wildcard domains. The origin includes the scheme and exact port if non-standard; the host entry does not include a scheme.

Do not copy the example hostname literally. Production startup intentionally refuses to continue until the correct values are configured.
