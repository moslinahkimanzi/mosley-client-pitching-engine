# Customer Gmail integration setup

MCAS uses one Google OAuth web application owned by the MCAS operator. Each MCAS customer connects their own Google account. Refresh tokens are encrypted server-side and associated with that MCAS user account.

## What MCAS does

- Requests only the Gmail `gmail.compose` OAuth scope.
- Creates a Gmail draft from an email draft that the customer has reviewed and saved.
- Does not list, search, read, monitor or delete incoming mail.
- Has no Gmail send endpoint and does not send messages.
- Keeps the MCAS copy if Gmail draft creation fails; the customer can retry from the saved draft list.
- Creates Gmail drafts only for the currently signed-in customer's own connected account.

Important Google permission note: Google classifies `gmail.compose` as a **restricted** Gmail scope. Although MCAS code only calls the Gmail drafts-create endpoint, Google's scope description says it can manage drafts and send email. The permission itself is broader than MCAS's implemented behaviour. Do not claim that Google technically prevents sending. Public use can require Google OAuth verification and, when restricted-scope data is stored or transmitted by a server, a security assessment. Review Google's current requirements before opening the integration to the public.

## Local development setup

1. Open Google Cloud Console and create/select a dedicated development project.
2. Enable the Gmail API for that project.
3. Configure the Google Auth Platform consent screen. Use External for testing with personal Google accounts, add the required app name, support email, developer contact and privacy-policy details.
4. While the app is in Testing, add each tester's Google account to the Test users list. Google currently limits test users and test-mode refresh-token lifetimes; do not treat this as a public production setup.
5. Create an OAuth client ID of type **Web application**.
6. For local development, add this exact authorised redirect URI:
   `http://localhost:8000/api/integrations/gmail/callback`
7. Copy the OAuth Client ID and Client Secret into your local `.env` file only. Do not commit or paste them into chat.

Set these server-side variables:

```dotenv
GMAIL_CLIENT_ID=your-google-oauth-client-id
GMAIL_CLIENT_SECRET=your-google-oauth-client-secret
GMAIL_REDIRECT_URI=http://localhost:8000/api/integrations/gmail/callback
MCAS_ENCRYPTION_KEY=your-generated-fernet-key
```

Generate the encryption key with:

```bash
cd ~/mosley-client-pitching-engine
source .venv/bin/activate
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Use the generated key as `MCAS_ENCRYPTION_KEY`. Keep it stable and backed up securely: changing it makes previously stored Gmail refresh tokens undecryptable. Never commit `.env` or share its values.

Restart MCAS after editing `.env`. Use one hostname consistently: if the redirect URI uses `localhost`, open MCAS at `http://localhost:8000`, not `127.0.0.1`.

## Customer workflow

1. Customer signs in to their own MCAS account.
2. Customer opens **Integrations** and chooses **Connect Gmail**.
3. Customer signs in to Google and grants the requested permission.
4. Customer generates an outreach email, verifies the recipient and edits the message.
5. Customer saves the email. MCAS stores its own draft and, when Gmail is connected and a recipient is present, creates a matching Gmail draft.
6. Customer opens Gmail Drafts, reviews the message and sends it manually if they choose.

If Gmail is not connected or draft creation fails, the MCAS draft remains available. The customer can connect Gmail or retry creating the Gmail draft later.

## Production requirements

Before enabling customer connections on a public MCAS domain:

- Deploy HTTPS and choose the final canonical hostname.
- Change `GMAIL_REDIRECT_URI` to the exact production callback, e.g. `https://YOUR_DOMAIN/api/integrations/gmail/callback`.
- Add that exact URI under the OAuth web client authorised redirect URIs.
- Configure the production app domain, verified ownership, privacy policy, terms, support contact and consent-screen branding.
- Submit the OAuth app for the applicable Google verification. Because `gmail.compose` is restricted, assess the required restricted-scope security assessment before public launch.
- Ensure the privacy policy explains token storage, use, retention, disconnection and deletion.
- Test with at least two separate MCAS accounts connected to two separate Google accounts. Confirm drafts never cross accounts.
- Test disconnect/reconnect, token refresh, expired/invalid state, denied consent and provider outages.
- Do not use your development OAuth client for production.

Google documentation:
- Gmail scopes and verification: https://developers.google.com/workspace/gmail/api/auth/scopes
- OAuth web-server flow: https://developers.google.com/identity/protocols/oauth2/web-server
- Gmail server-side authorization: https://developers.google.com/workspace/gmail/api/auth/web-server
- Google Workspace user-data policy: https://developers.google.com/workspace/workspace-api-user-data-developer-policy
