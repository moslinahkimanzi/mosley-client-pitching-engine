# MCAS Updates and Continuous Improvement

## Hosted SaaS release model

The Updates page reports the version configured on the MCAS server and displays release notes. MCAS is centrally operated as a hosted SaaS: the operator reviews, tests and deploys a release once; customers do not download or install server code.

The version is controlled by `MCAS_VERSION`. Change it when preparing a centrally deployed release and update the release notes in `backend/app.py`. A displayed version is release information from the server, not an independent proof of deployment health or security.

## Customer feedback and AI consent

Customers can submit bug reports, usability feedback, feature requests, security concerns and other feedback. They can see only feedback associated with their account. Existing feedback and new submissions default to no AI-analysis consent.

A customer may explicitly consent at submission time to having the feedback title and text sent to the configured AI provider for product-improvement analysis. The consent is optional. Customers can withdraw consent later from their feedback history. Withdrawal prevents future analysis; it cannot undo processing already performed by an external provider.

Security-category feedback is excluded from AI analysis even when consent is selected. Security reports should be reviewed through a controlled human security process.

Before external AI processing, MCAS attempts to redact common email addresses, phone/number patterns, URLs, credential patterns, cloud access-key patterns, IP addresses and long numeric sequences. This is best-effort redaction, not anonymisation or a guarantee that all personal or confidential content is removed. Feedback text can still contain names, business details, addresses or other identifying information. Customers must not submit passwords, API keys, tokens, private prospect records or sensitive personal information.

## AI improvement analysis limits

An administrator manually starts analysis. Each run processes at most 20 new opted-in, non-security feedback items; text sent to AI is individually length-limited. MCAS validates the AI response and stores prioritised recommendations and test ideas. Previously analysed feedback is not sent again.

`MCAS_AI_IMPROVEMENT_MONTHLY_LIMIT` sets a shared per-server limit on feedback-analysis attempts per UTC month (default 10; permitted range 1–1000). Failed provider calls also consume an attempt. The limit is an application request cap, not a monetary spending cap or a guarantee of a particular provider bill. AI provider usage, pricing and other AI assistant calls must be monitored separately.

AI output is a proposal, not verified fact. It can be incomplete or wrong. An authorised operator must validate the issue, reproduce it, write or update tests, implement changes on a feature branch, inspect the diff, wait for CI and CodeQL, test in staging, back up production data, and approve the hosted deployment. This workflow does not generate or execute code, merge branches, change security settings or deploy automatically.

## Administrator bootstrap and MFA

Set `MCAS_ADMIN_EMAILS` to the exact email address or addresses authorised for administrator access. Administrator emails are not self-selected inside MCAS.

Set a separate random `MCAS_ADMIN_BOOTSTRAP_TOKEN` (at least 32 characters; generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`). Set `MCAS_ADMIN_MFA_ENCRYPTION_KEY` as described below. The bootstrap token is required both when registering a configured administrator account and when enrolling its first authenticator. Existing administrator accounts must also provide this token during first MFA setup, so a previously claimed email address alone is not sufficient.

Each configured administrator must enrol a time-based one-time password (TOTP) authenticator using HMAC-SHA-256. MFA secrets are encrypted in the database using a separate `MCAS_ADMIN_MFA_ENCRYPTION_KEY`. Generate it with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`, place it only in the server's private environment, and keep it stable and protected. Losing or changing it prevents stored TOTP secrets from being decrypted. Use an authenticator app and keep the setup secret in a secure offline location. MCAS does not yet issue recovery codes; keep a second authenticator securely enrolled during setup or use a controlled operator recovery procedure.

After all configured administrators have enrolled MFA, remove `MCAS_ADMIN_BOOTSTRAP_TOKEN` from the runtime environment. Add it temporarily again only for an authorised new administrator provisioning event, then remove it after setup. Never commit the token or share it in support tickets.

MFA is enforced on every new administrator sign-in. The password step creates a short-lived challenge; five invalid authenticator codes invalidate that challenge. Initial authenticator enrollment is also limited to five incorrect codes; the pending setup is cancelled and must be restarted after five failures. Opaque session, MFA-challenge and OAuth state tokens are stored as HMAC-SHA-256 digests keyed by the stable server signing secret; this is separate from password storage, which uses PBKDF2. Because the token-digest format changes from unkeyed SHA-256, deployment invalidates existing sessions and pending OAuth state once, and customers/operators must sign in again. Enabling MFA revokes the setup session, requiring a fresh password-plus-authenticator sign-in. Customer accounts do not yet have MFA in this release.

## Security Guardian and external controls

The Administrator Maintenance page includes a Security Guardian configuration summary. It checks application settings such as production mode, signing-secret quality, administrator MFA enrollment, AI endpoint allowlisting and the monthly analysis cap. It is not a penetration test, vulnerability scan or proof that the hosted environment is secure.

The following protections still require external setup and verification:

- Database encryption at rest: MCAS does not encrypt the SQLite database file. Use encrypted storage or a managed database that provides encryption at rest.
- Encrypted off-site backups: configure backup storage and encryption with the hosting provider, store backup keys separately, and regularly test restoration.
- Customer email verification: registration does not verify email ownership in this release. Use a verified-email flow before broad public signup.
- GitHub branch protection: configure required CI and CodeQL checks and restrict direct pushes to `main` in GitHub repository settings.
- Production perimeter and monitoring: configure HTTPS, host allowlists, WAF/rate limiting, alerting and incident procedures at the hosting/provider layer.
- Production replicas: SQLite-based rate limiting and the AI quota are shared only by processes using the same database file. Multi-instance hosting needs a shared production database or external rate-limit/usage service.

## Continuous maintenance

The repository includes pull-request CI, CodeQL analysis, Dependabot proposals and a scheduled weekly regression/dependency audit. These checks report findings; they do not automatically upgrade dependencies, merge pull requests or deploy production code.

Review every dependency update on a separate branch, inspect the diff, run CI and CodeQL, test in staging, take and verify a backup, then require an authorised human to approve deployment.

## Explicit safety boundaries

- AI feedback analysis creates structured improvement proposals only; it does not generate or execute code.
- No self-modifying production code.
- No automatic merge or production deployment.
- No automatic change to security configuration.
- No access to customer Gmail inboxes or automatic email sending.
- No cross-customer use of private feedback or workspace data.
- Configuration dashboards are not live scan results; verify external services directly.
