# Mosley Client Acquisition System (MCAS)

An early browser-based prototype for managing website-development prospects and preparing outreach drafts.

## Run locally
No build tools or paid API keys are required.

1. Download or clone this repository.
2. Open `index.html` in Firefox, Chrome, or another modern browser.

Or from the repository directory run:
```bash
python3 -m http.server 8000
```
Then visit http://localhost:8000.

## Included in this prototype
- Prospect list and manual prospect entry
- Evidence-conscious cold-email draft generator
- Rule-based client reply drafting
- Pending-approval draft list
- Basic do-not-contact response handling
- Browser-local persistence using localStorage

## Not yet implemented
- Live web-wide prospect discovery or automated website auditing
- Gmail/IMAP inbox connection or email sending
- AI model integration
- Cloud database, user accounts, multi-tenant isolation, billing
- Production-grade authentication/security

This prototype is not a production SaaS and should not be used to store sensitive personal information. Verify all prospect details and comply with applicable privacy and direct-marketing laws. No email is sent by this application.

## Security
Do not add API keys or passwords to client-side code. A production release needs a server-side backend, secure authentication, authorization, tenant isolation, secret management, rate limiting, backups, audit logs and security testing.
