# Gmail draft integration — local setup

This guide configures Gmail draft creation for a local MCAS development server. It does not configure a public production service.

## Permission boundary

MCAS requests `https://www.googleapis.com/auth/gmail.compose`. Google classifies this as a **restricted scope**. The scope can technically create, read, update and delete drafts and send messages. The current MCAS implementation calls the Gmail drafts-create endpoint only; it does not read, search, list, monitor or send email. There is no MCAS send endpoint. The user must open Gmail and send a draft manually.

Do not publish a public Gmail connection until Google OAuth verification and any required restricted-scope security assessment have been completed.

## 1. Enable the Gmail API

1. Open Google Cloud Console and select the same development project used for MCAS.
2. Open **APIs & Services → Library**.
3. Search for **Gmail API** and click **Enable**.

## 2. Configure the OAuth consent screen for local testing

1. Open **Google Auth Platform → Audience**.
2. Keep the app as **External** and in **Testing** while doing local tests.
3. Add the Google account you will use to test Gmail as a test user.
4. Open **Google Auth Platform → Data Access**.
5. Add this scope for local testing:

   `https://www.googleapis.com/auth/gmail.compose`

6. Do not add inbox-reading scopes such as `gmail.readonly`, `gmail.metadata` or `gmail.modify`.

Google may show an unverified-app warning during local testing. Only proceed with your own test account and only when you recognise the MCAS OAuth project and requested permission.

## 3. Create the Gmail OAuth Web client

Create a Web application OAuth client (you can create a second client in the same Cloud project, separate from the Sign-In client, to keep the two flows clear).

Set its authorised redirect URI to this exact value:

```text
http://localhost:8000/api/integrations/gmail/callback
```

The redirect URI in Google Cloud Console and `GMAIL_REDIRECT_URI` in MCAS must match exactly, including scheme, host, port, path and trailing slash behaviour.

For this guide, open MCAS using `http://localhost:8000` while connecting Gmail. Do not switch between `localhost` and `127.0.0.1` during the OAuth round trip. The GIS sign-in client separately uses authorised JavaScript origins; its local entries are:

```text
http://localhost:8000
http://127.0.0.1:8000
```

Copy the Gmail OAuth **Client ID** and **Client secret** from Google Cloud Console. These are different configuration values from the sign-in Client ID setting.

## 4. Generate an encryption key

MCAS encrypts each customer's Gmail refresh token before storing it in the local database. Generate one Fernet key in the project's virtual environment:

```bash
cd ~/mosley-client-pitching-engine
source .venv/bin/activate
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the generated value somewhere safe. Do not send it in a chat, commit it to GitHub, or regenerate it after Gmail accounts have been connected. Losing or changing this key prevents MCAS from decrypting previously stored Gmail refresh tokens; affected users must reconnect.

## 5. Add the settings to the private .env file

Open the existing file:

```bash
cd ~/mosley-client-pitching-engine
nano .env
```

Add or update these entries. Replace the example values with the credentials you copied. Keep all the other existing settings in your file:

```dotenv
GMAIL_CLIENT_ID=your-gmail-web-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=your-gmail-web-client-secret
GMAIL_REDIRECT_URI=http://localhost:8000/api/integrations/gmail/callback
MCAS_ENCRYPTION_KEY=your-generated-fernet-key
```

Save with **Ctrl+O**, press **Enter**, then exit with **Ctrl+X**.

The `.env` file is ignored by Git, but do not paste it into GitHub, screenshots, email or chat. Never put the client secret or encryption key in `index.html` or `assets/app.js`.

## 6. Restart MCAS

Stop the running Uvicorn server with **Ctrl+C** in its terminal, then start it again:

```bash
cd ~/mosley-client-pitching-engine
source .venv/bin/activate
set -a
source .env
set +a
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

For this Gmail test, open:

```text
http://localhost:8000
```

If the browser still has an active MCAS session, sign in with Google, open **Integrations**, and check the Gmail status badge. It should say **Ready to connect** when server credentials and the encryption key are valid.

## 7. Connect and test draft creation

1. Open **Integrations → Google Gmail → Connect Gmail**.
2. Choose the test Google account, review the permission, and approve only if the project and permission are expected.
3. MCAS should return to the app with `gmail=connected`; the status badge should say **Connected**.
4. Open **Email studio**. Use a test recipient address that you control, generate a message, and save it.
5. In the saved-drafts list, choose **Create Gmail draft** for that saved message and confirm.
6. Open Gmail → **Drafts** and confirm the message is there. Confirm that it remains unsent.
7. Optionally click **Disconnect** in MCAS and confirm the badge changes. Disconnect removes MCAS's stored connection; it does not delete drafts already created in Gmail.

## Troubleshooting

- **Gmail integration is not configured:** one or more of `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, `GMAIL_REDIRECT_URI` or `MCAS_ENCRYPTION_KEY` is missing or invalid; restart the server after correcting `.env`.
- **redirect_uri_mismatch:** the callback URL in Google Cloud Console must exactly equal `http://localhost:8000/api/integrations/gmail/callback`.
- **Access blocked / app not verified:** confirm the account is listed as a test user, the app remains in Testing, and the Gmail compose scope is configured. This test setup is not public-launch approval.
- **No refresh token:** reconnect and consent again; MCAS asks Google for offline access and explicit consent.
- **Invalid encryption key:** generate a valid Fernet key in the same virtual environment. Do not overwrite an existing key if stored connections already depend on it; recover the original key or have users reconnect after a controlled local reset.
- **Draft fails:** confirm the recipient address is valid, the Gmail account has permission to create drafts, the API is enabled and the access token has not been revoked.

## Production is a separate project milestone

For a real customer launch, use a stable HTTPS hostname, production OAuth credentials, a verified domain and public privacy disclosures, a published consent screen and Google's verification process for the restricted Gmail scope. Google may require an independent security assessment when restricted-scope data is accessed or stored on a server. Do not promise customers a verified Gmail connection until Google's review and any required assessment are complete.
