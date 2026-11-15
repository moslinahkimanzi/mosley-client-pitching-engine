# Security Policy

## Reporting a vulnerability
Do not disclose a suspected vulnerability in a public issue. Contact the repository owner privately through GitHub's private vulnerability reporting feature when available. Include affected version/commit, reproducible steps, impact and a suggested mitigation. Do not include customer data, credentials, tokens or secrets.

## Security design
- Customer records are scoped by authenticated user ID in application queries.
- Mutating browser requests require same-origin CSRF protection.
- Production rejects wildcard origins/hosts and requires explicit configured application hosts.
- Shared SQLite-backed request limits protect workers sharing one database file; deployments with multiple independent database replicas must use a central rate-limit service or API gateway.
- Website auditing uses public-address validation, pinned destination IPs, restricted ports and bounded redirects.
- AI evidence and pasted messages are untrusted content. AI output is text for human review; the AI has no direct database or server tool permissions.
- Gmail integration is draft-only. MCAS does not read incoming email and does not expose an email-send endpoint.

## Known operational requirements
Application code cannot enable MFA, WAF/DDoS controls, immutable remote backups, encrypted cloud volumes, branch protection or private vulnerability reporting in the owner's hosting/GitHub accounts. See SECURITY-OPERATIONS.md before production launch.
