# MCAS Security Review — 21 November 2026

## Scope and confidence
This is a source-code review of the repository development line based on inspection of the FastAPI backend, browser JavaScript, security tests, configuration examples and CI workflows. It is not a live penetration test, infrastructure review, authenticated two-tenant test against a deployed host, or independent third-party assessment. No production secrets, customer records or live exploit attempts were used.

Reference baseline: OWASP ASVS 5.0.0. Use the ASVS requirements as a verification checklist, not as a certification claim.

## Positive controls observed
- Passwords are stored as PBKDF2-HMAC-SHA256 hashes with per-user random salts and 310,000 iterations.
- Session and OAuth opaque tokens are stored as keyed digests rather than plaintext.
- Session cookies are HttpOnly, SameSite=Lax and Secure in production; CSRF cookie is SameSite=Strict and paired with a validated header token.
- Mutating requests require CSRF validation; configured origins and trusted hosts are checked.
- Authenticated routes use server-side ownership checks for prospects and related records; tests cover cross-tenant prospect isolation and foreign lead attachment.
- Administrator identities are operator-configured, administrator MFA is supported and production rejects password-only admin mode.
- New customer registrations require email verification in the current account-email-verification development line; legacy accounts are migrated as verified.
- Gmail refresh tokens are encrypted at rest when the configured Fernet key is present. MCAS requests gmail.compose, creates drafts only, and has no implemented send or inbox-reading route.
- Website fetches validate public IP addresses, pin the resolved IP for the connection, restrict ports to 80/443, revalidate redirects, and block HTTPS-to-HTTP downgrade.
- AI prompts classify external search results, prospect evidence and pasted customer text as untrusted data.
- CI includes Python compilation, unit tests, JavaScript syntax checks, pip-audit and CodeQL workflow configuration.

## Findings

### High — customer accounts do not have MFA
Administrator authenticator MFA exists, but ordinary customer accounts use email/password only. A compromised customer password can expose that customer's prospect and proposal workspace. Add customer MFA or integrate a verified identity provider with risk-appropriate step-up authentication.

### High — no self-service password recovery
A customer who loses a password has no secure in-product reset flow. Do not implement recovery using security questions or support staff asking for passwords. Add expiring single-use reset tokens, store only keyed hashes, rate-limit issuance and consumption, notify the account owner, and revoke all active sessions after a successful reset.

### High — request-body size guard trusts Content-Length
The middleware rejects requests whose declared Content-Length exceeds the configured maximum. Requests without Content-Length (for example, streamed/chunked requests) are not bounded by that check at the application layer. A reverse proxy/WAF must enforce hard request-body limits; add an ASGI receive-stream byte counter so the application itself rejects oversized bodies regardless of transfer framing, then test chunked requests.

### Medium — long-lived sessions have no inactivity timeout
The current absolute session lifetime is 14 days. There is no separate idle timeout, device/session inventory or user self-service revocation of individual sessions. Define risk-based idle and absolute lifetimes, record last activity, add session management and revoke sessions on credential/security changes.

### Medium — customer password policy is length-only
Registration enforces a minimum length but does not check compromised/common passwords or provide password-strength guidance. Add breached-password screening using a privacy-preserving method, avoid arbitrary composition rules, and keep rate limits and MFA.

### Medium — SQLite rate limiting is deployment-topology dependent
The rate limiter coordinates workers only when they share the same SQLite database file. It does not coordinate separate containers/hosts or regions. Behind a reverse proxy, request.client.host may identify the proxy rather than the real client; do not trust arbitrary forwarded headers. Enforce limits at the WAF/API gateway and move shared counters to Redis or another atomic shared service before horizontal scaling.

### Medium — request body and response limits need deployment-level enforcement
The site fetcher bounds HTML reads and outbound ports, but the deployment must also cap inbound bodies, response times, concurrent audits, and worker queues. Competitor runs may perform several sequential outbound fetches; use bounded worker concurrency and a total request deadline before high-volume use.

### Medium — SQLite data file is not application-encrypted
Gmail refresh tokens and MFA secrets are encrypted individually, but prospect records, proposals, audit logs and other SQLite fields are not encrypted by MCAS itself. Require encrypted persistent volumes or move to a managed database with encryption at rest, TLS, least-privilege access and tested backups.

### Medium — backups and restore process are external/unverified
The repository documents that off-site encrypted backups and restore tests must be configured. No code review can confirm the host's backup policy. Store immutable encrypted backups under a separate identity and regularly test restores.

### Medium — audit logs are not tamper-proof
Security events are emitted to normal application logs and the audit_log table is writable by the application database identity. Forward security events to a separately controlled append-only logging service/SIEM and alert on unusual login, admin, export, and secret-access activity.

### Medium — email verification delivery and production OAuth still need live validation
The code path for email verification is implemented in the development branch, but a real SMTP sender/domain, TLS, link delivery and browser flow must be tested on the production domain. Gmail's gmail.compose scope is broad enough to permit sending at the Google permission level even though MCAS does not implement or invoke a send endpoint. Google OAuth verification/restricted-scope review may be required for public use.

### Low — customer-facing security labels were stale
The Security & Plans UI and admin security-status endpoint previously stated that customer email verification was not implemented, even though the account-verification branch contains it. This feature branch corrects those labels and explicitly reports customer MFA and account recovery as missing.

### Low — security tests are useful but not comprehensive
Existing tests cover selected CSRF, origin, tenant-isolation, do-not-contact, rate-limit, headers, MFA and account-verification cases. They do not constitute exhaustive authorization/property-level tests, a deployed SSRF/DNS-rebinding test, fuzzing, concurrency tests, browser automation, or a penetration test.

## Audit feature security constraints
- Website audits use the existing SSRF-hardened fetch path and do not execute page JavaScript.
- Competitor lookup requires an authenticated prospect owned by the caller and uses dedicated rate limits.
- Candidate competitor records and provider ratings remain unverified.
- Static missing-header checks are review findings, not proof of an exploitable vulnerability.
- No arbitrary code execution, port scanning, exploit payloads, malware execution or automated outreach is performed.

## Required actions before public paid launch
1. Enforce inbound body limits at the edge and in ASGI, including chunked requests.
2. Add customer MFA and secure password recovery.
3. Add idle session expiry, session inventory and global session revocation.
4. Use managed PostgreSQL for multi-instance production; configure TLS and encryption at rest.
5. Configure WAF/DDoS protection, trusted reverse-proxy behavior, edge rate limits and bounded audit worker concurrency.
6. Configure immutable encrypted off-site backups and test restore procedures.
7. Forward security logs to a separate protected destination with alerts.
8. Protect GitHub main with required CI/CodeQL, restrict workflow edits and force pushes, and enable secret scanning/push protection where available.
9. Validate production SMTP and Google OAuth scope/verification.
10. Run independent penetration testing against the deployed service, including BOLA/IDOR, session management, CSRF, SSRF/DNS rebinding, auth recovery, rate limits, XSS, prompt injection and tenant isolation.

## Overall assessment
The repository contains a meaningful baseline of defensive controls and several targeted security tests. It is not yet ready to be described as production-secure or independently verified. The most important application gaps are customer MFA, password recovery, idle session management and robust body-size enforcement. Infrastructure gaps include WAF/rate limiting, encrypted database storage, immutable backups, external monitoring and branch protection.
