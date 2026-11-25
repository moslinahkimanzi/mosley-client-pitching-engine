# Google sign-in and local startup

## Google Identity Services setup

MCAS uses Google Identity Services (GIS) to authenticate users. The browser receives a Google ID token; the backend verifies the RS256 signature, issuer, audience, expiry, verified-email claim and one-time nonce before creating a session.

1. Open Google Cloud Console and select or create a project.
2. Configure the OAuth consent screen and publish it / add the required test users as appropriate for your Google account setup.
3. Create an OAuth client ID of type **Web application**.
4. Under **Authorised JavaScript origins**, add the exact origins used by MCAS. For local testing add:
   - `http://localhost:8000`
   - `http://127.0.0.1:8000`
   For hosted use, add the exact HTTPS origin, for example `https://app.example.com`.
5. Copy the client ID. GIS uses an ID-token callback in the page; this flow does not need a separate redirect URI.
6. Add the client ID to your private server `.env`:

```bash
GOOGLE_CLIENT_ID=your-google-web-client-id.apps.googleusercontent.com
```

Never put a Google client secret, AI key, Serper key or database credential in `index.html`, `assets/app.js` or any public repository file. This GIS flow uses the public client ID only; the server verifies the signed ID token.

## Administrator identity

Put the exact Google account email that should receive administrator access in the private server `.env`:

```bash
MCAS_ADMIN_EMAILS=your-google-account@gmail.com
```

Separate multiple administrators with commas. An administrator must sign in with a Google account whose email Google marks as verified and whose address exactly matches this allowlist. The admin maintenance menu and every admin API endpoint are separately protected server-side.

New Google sign-ins create an MCAS workspace automatically. Existing password-based accounts can be linked to the matching Google identity after Google verifies the same email. In production, the legacy password registration and login endpoints return HTTP 410 and cannot be used to create an allowlisted admin account. There is no email verification link or user-visible bootstrap tab.

## USD project estimates

MCAS converts its Kenya-scope planning bands to USD using `MCAS_KES_PER_USD`. The example value is 130.00 KES per USD, based on the Central Bank of Kenya indicative US dollar rate published for 20 November 2026. Update the value in `.env` when you want a newer planning rate:

```bash
MCAS_KES_PER_USD=130.00
```

This is an estimate only, not a quote or a live bank/card conversion. The estimate is rounded to the nearest USD 25 and excludes tax, paid third-party services and unconfirmed scope.

## Local Ubuntu startup

From the project directory, stop an old server with `Ctrl+C` first, then run:

```bash
cd ~/mosley-client-pitching-engine
source .venv/bin/activate
set -a
source .env
set +a
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in the same computer's browser. The origin used in Google Cloud must exactly match the address used in the browser. Use HTTPS and an exact production hostname when deploying publicly; do not expose the development server directly to the internet.

If the virtual environment has not been created yet:

```bash
cd ~/mosley-client-pitching-engine
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Verification commands

```bash
python -m compileall -q backend tests
python -m unittest discover -s tests -v
node --check assets/app.js
```

The admin feature test lab can produce QA plans from AI suggestions, run synthetic website-status acceptance scenarios and perform a bounded read-only audit of a public website. It does not execute AI-generated code or deploy features. Run actual functional/e2e tests in a separate staging deployment before enabling a change for customers.

## Website audit limitations

The public auditor is intentionally bounded to a maximum of 15 same-host pages. It analyses HTTP responses, basic HTML metadata, links, images/alt attributes, form-label signals, mixed HTTP content and selected response security headers. It does not run browser JavaScript, inspect authenticated pages, submit forms, scan ports, exploit vulnerabilities or certify a website as secure. A website marked **Verified** means MCAS observed a successful public HTTP response at the checked URL; it does not prove business ownership or complete functionality. A missing listing URL is categorised as **No website link found**, not as proof that no website exists.
