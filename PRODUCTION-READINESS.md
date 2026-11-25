# MCAS production readiness record

**Current decision: PRE-LAUNCH — NOT APPROVED FOR PUBLIC COMMERCIAL PRODUCTION**

This record separates verified repository controls from tasks that require real infrastructure, provider approval, or an independent reviewer. A status is not marked complete merely because a configuration option or code path exists.

## Verified on the release candidate

Candidate branch: `release/mcas-prelaunch-2026-11`

GitHub Actions run [#900](https://github.com/moslinahkimanzi/mosley-client-pitching-engine/actions/runs/45563715546), commit `8078e79b1bbcefe60aa3931d43431627bf43b868`, completed successfully on 25 November 2026:

- Python compilation: passed.
- Automated Python test suite: 89 tests passed.
- Front-end JavaScript syntax check: passed.
- `pip-audit -r requirements.txt`: no known vulnerabilities reported for the pinned dependency set at that run.
- This is a repository CI check. It is not a penetration test, hosted end-to-end test, or production deployment verification.

## Implemented in this candidate

| Area | Evidence-based status |
|---|---|
| Google customer identity | Implemented. The production login flow verifies Google OIDC signatures, audience, nonce, token times and the `email_verified` claim. Local password registration/login are disabled in production; Google handles account recovery. |
| Administrator privileges | Implemented. The server matches the signed-in database user against `MCAS_ADMIN_EMAILS`; production also requires a linked verified Google subject. |
| Administrator MFA | Implemented in code. Production startup requires MFA and a separate Fernet encryption key. TOTP enrollment, challenge sign-in, replay protection, attempt limits and one-time recovery codes are included. The real administrator must still enroll after production configuration. |
| Administrator billing exemption | Implemented. Allowlisted administrators do not purchase subscriptions or credit packs. Unlimited usage is activated only after required MFA enrollment and is audit logged. Browser-provided roles are not trusted. |
| Workspace service prices | Implemented. Eight website-service entries are editable per workspace, persisted by tenant, validated server-side and reflected in Services & Pricing. They are separate from MCAS subscriptions and prepaid credits. |
| Payment ledger and verification foundation | Implemented in code, but live payment is disabled. Hosted checkout and webhook verification code do not establish merchant approval or settlement readiness. |
| Gmail | Draft-creation behavior only. MCAS does not read or search incoming mail and does not provide a send endpoint. Google `gmail.compose` is broader at OAuth permission level than draft creation alone; review this scope during OAuth consent verification. |
| Feedback-led improvement | Supervised only. Opted-in feedback can produce proposals and tests for administrator review; the system does not autonomously edit or deploy application code. |

## Still outstanding — production blockers

| Requirement | Current status | Evidence required to change status |
|---|---|---|
| Hosting provider and production environment | Not configured | Named host, production app, environment configuration and a successful staging deployment. |
| Domain and HTTPS | Not configured | Owned domain, DNS records, valid TLS certificate, trusted host/origin configuration and externally verified HTTPS. |
| Database for production scale | SQLite single-instance only | Managed PostgreSQL migration, migration test, tenant-isolation tests and restore test. Do not run multiple app instances against the current SQLite file. |
| Shared rate limiting | Single-instance only | Shared Redis (or equivalent) implementation, configured production service and multi-instance abuse tests. |
| Backups and recovery | External action required | Encrypted off-site backups, documented retention, a successful restore drill and named recovery owner. |
| Monitoring and incident response | Not verified | Error/uptime alerts, security-event retention, escalation contact and incident-response procedure. |
| Administrator enrollment | Not yet performed | Set the admin email allowlist and required MFA secrets in the host secret manager; enroll the real admin Google account and securely store all recovery codes. |
| Independent security assessment | Not performed | Independent penetration test, written findings and verified remediation. CI and dependency audits do not replace it. |
| M-Pesa merchant onboarding | Not verified | Provider/Safaricom merchant KYC and written approval for the selected product and settlement destination. |
| M-Pesa sandbox and live settlement | Not verified; billing disabled | Successful sandbox test, live webhook validation, reconciliation/refund procedures and a real test settlement to the intended account. Keep `MCAS_BILLING_ENABLED=false` until these pass. |
| Public legal and customer-support documents | Not ready | Reviewed privacy notice, terms, payment/refund policy, data retention/deletion process and support contact appropriate to the business and jurisdictions served. |
| Hosted acceptance test | Not run | Registration/login, tenant isolation, research, website audit, proposal, workspace prices, admin MFA, billing disabled/enabled test paths, backups and restore tested on the exact staged release. |

## Payment restrictions

- `MCAS_BILLING_ENABLED=false` remains the safe default.
- Card checkout is disabled in this release.
- Monthly M-Pesa subscription renewal is customer initiated; automatic recurring M-Pesa charges are not implemented.
- A successful checkout redirect or STK initiation is not proof of payment. Only a verified provider event and server-side transaction check may grant value.
- Do not accept customer money until merchant approval, webhook testing, settlement and reconciliation are complete.

## Go-live rule

Do not merge to the live deployment branch or deploy this candidate until all production blockers above have documentary or test evidence, the exact candidate commit passes CI, an independent security review is complete, and a staged acceptance test is signed off. Deployment must be announced to the operator before the deployment action and must include a rollback plan.