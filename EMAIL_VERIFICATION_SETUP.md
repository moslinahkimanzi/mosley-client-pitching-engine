# MCAS account email verification

MCAS verifies that a new customer controls the email address used to register. This is separate from the customer's Gmail integration. MCAS sends account-verification messages from an operator-configured SMTP sender; it never uses customer Gmail credentials to send account mail.

## Behaviour
- New registrations create an inactive account and do not issue a login session.
- The customer receives a single-use verification link valid for 24 hours.
- Only a hash of the random verification token is stored in SQLite.
- Opening the link with GET does not consume the token. The user must deliberately click Confirm email address; this prevents common email link-preview scanners from verifying accounts automatically.
- The token is consumed on successful confirmation and cannot be reused.
- Login and protected workspace API routes reject unverified accounts.
- Customers can request another link. The old link is invalidated; resend requests are rate-limited and return a generic response to reduce account enumeration.
- Existing accounts are preserved as verified by the migration.
- In local development only, if SMTP is not configured, MCAS shows a local verification action. This convenience is disabled in production.

## Configure the email sender

Use a dedicated transactional email sender or an SMTP account controlled by the MCAS operator. Do not use a customer's connected Gmail account. Do not ask customers for email passwords or SMTP credentials.

Set these values in the server's private .env or production secret manager:

```dotenv
MCAS_PUBLIC_BASE_URL=https://YOUR_PUBLIC_DOMAIN
MCAS_EMAIL_SMTP_HOST=your-provider-smtp-host
MCAS_EMAIL_SMTP_PORT=587
MCAS_EMAIL_SMTP_USERNAME=your-smtp-username
MCAS_EMAIL_SMTP_PASSWORD=your-smtp-password
MCAS_EMAIL_SMTP_USE_SSL=false
MCAS_EMAIL_SMTP_STARTTLS=true
MCAS_EMAIL_FROM=verified-sender@your-domain
MCAS_EMAIL_FROM_NAME=Mosley MCAS
```

For implicit TLS on port 465, use MCAS_EMAIL_SMTP_USE_SSL=true and MCAS_EMAIL_SMTP_STARTTLS=false. Production rejects configurations without TLS. Use the exact SMTP host, port and TLS mode documented by your email provider.

The sender domain should have SPF and DKIM configured, and preferably DMARC, before public launch. Verify the sending domain with the provider. Do not publish until test messages reliably arrive rather than going to spam.

## Local development

The default .env.example uses http://localhost:8000. If SMTP is not configured and MCAS_ENV=development, a local-only verification URL is returned by the registration/resend API and displayed as a Confirm email address button in the browser. This is for local testing only and is not a public delivery mechanism.

## Production checklist
- Use the canonical public HTTPS domain in MCAS_PUBLIC_BASE_URL.
- Configure an authenticated SMTP sender with TLS and verify the sender domain.
- Store SMTP credentials in a secret manager or a private .env with restrictive permissions; never commit them, print them in logs, or paste them into chat.
- Ensure outgoing TCP to the provider's SMTP endpoint is permitted by the hosting provider.
- Test delivery, expiry, single-use behaviour, resend throttling, wrong-token handling and recovery after SMTP outage.
- Monitor delivery failures without logging verification URLs or tokens.
- Provide a support route for customers who no longer control their registered email address.
- Back up the database. Keep MCAS_SECRET_KEY stable because token hashes are keyed with the application secret.
- Review applicable privacy, retention and email-delivery requirements before public launch.

Email verification proves control of an email inbox at the time of confirmation. It does not prove a customer's legal identity.