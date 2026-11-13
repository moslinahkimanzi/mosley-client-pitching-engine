# MCAS pre-publication test plan

For the current research-completion build, use branch \`feature/mcas-research-completion\`. It is an open feature branch, not the default \`main\` branch. Preserve your local \`.env\` and \`data/mcas.db\` when switching branches; never run \`git reset --hard\` or delete local data to update the build.

## A. Automated checks

Run from the project root with the virtual environment active:

    python -m compileall -q backend tests
    python -m unittest discover -s tests -v
    node --check assets/app.js
    pip-audit -r requirements.txt

All commands should exit successfully. Resolve dependency advisories before publishing. GitHub Actions also runs the repository checks on supported branch pushes and pull requests.

## B. Configure Serper and start locally

Add your Serper key to the server-side \`.env\` file:

    SERPER_API_KEY=your_private_key_here
    SERPER_GL=ke
    SERPER_HL=en

\`SERPER_GL\` is optional and selects the Google results region; \`SERPER_HL\` is the language. Do not place the key in browser JavaScript, screenshots, Git commits or chat messages.

Start MCAS:

    source .venv/bin/activate
    set -a
    source .env
    set +a
    uvicorn backend.app:app --host 127.0.0.1 --port 8000

Open http://localhost:8000 in Firefox. Use the same hostname consistently. Health endpoint: http://localhost:8000/api/health.

## C. Research workflow checks

1. Open Research → Research command centre.
2. Enter a location such as Nairobi.
3. Choose Salons and beauty businesses (or another category).
4. Enter an optional keyword such as \`braiding\`, \`barber\` or a business name.
5. Select 3 results first and press Start Research.
6. Confirm MCAS calls Serper Places and displays returned business names, categories, addresses, phone numbers and websites where provided.
7. When Places returns no records, confirm the Serper web-search fallback is used and its links are labelled as unverified source links, not official business websites.
8. Confirm each new result is saved to Prospects with status Unverified and a source link.
9. Confirm MCAS creates a website opportunity plan / proposal and an email draft pending your approval.
10. Confirm a missing website URL is described as not returned by Serper, not proof that no website exists.
11. Confirm no OpenStreetMap, Nominatim or Overpass service is required by the research run.
12. Repeat the same search within five minutes and confirm cached results avoid another provider request.
13. Try without a Serper key and confirm MCAS gives a clear configuration message rather than claiming a provider is temporarily unavailable.
14. Try an invalid Serper key and confirm the system surfaces a key/configuration error without exposing the key.
15. Check the Integration status: Web research should identify Serper as configured when \`SERPER_API_KEY\` is present.

## D. Gmail and outreach safety

- Gmail integration is compose-only. MCAS does not read, search, list or monitor incoming emails.
- A research run may create a Gmail draft only when a public email address is actually returned and Gmail is connected. Otherwise, the email remains a pending MCAS draft.
- Check Gmail Drafts and confirm the message has not been sent.
- No automatic send or follow-up-send action is implemented. Review every draft yourself before sending it manually.
- Do not contact a person or business where the source indicates an opt-out or where outreach is inappropriate.

## E. Other functional checks

1. Register a fresh test account with a unique email and a strong password.
2. Add a test prospect manually and verify dashboard counts update.
3. Mark a prospect Do Not Contact and confirm outreach drafting is blocked.
4. Save a draft, restart the server, sign in again and verify prospects and drafts persist.
5. Add a follow-up task, mark it complete and verify the status.
6. Generate and save a proposal.
7. Mark a test prospect as Client accepted / Won and generate the AI-builder prompt.
8. Paste a sample customer response manually into Reply Assistant. Confirm MCAS never asks to connect or read the inbox.
9. Export workspace data and store it securely; the export contains customer data.
10. Run a quick check against a website you control. Remember that it is not a full audit.
11. Open a second Firefox private window, register another user and confirm tenant data is isolated.
12. Put harmless markup such as \`<img src=x onerror=alert(1)>\` in a prospect name/evidence field. It should display as text, not execute.
13. Open DevTools → Network. Confirm same-origin \`/api/*\` and \`/assets/app.js\` requests load; session tokens must not be stored in localStorage.

## F. Security negative tests

Automated tests cover unauthenticated access, CSRF protection, tenant separation, private IPv4 rejection, salted password hashes and security headers.

Manual website-check tests: try localhost, a private LAN address, a non-standard port and an HTTPS URL redirecting to HTTP. These should be blocked. Do not test against third parties without permission.

## G. Stop before publishing if

- Any automated check fails or a dependency advisory remains unresolved.
- Data appears in the wrong account.
- A mutation works without a valid CSRF token.
- User-entered text executes as HTML or JavaScript.
- Website checks reach localhost, private IP ranges or metadata services.
- OAuth tokens appear in browser storage, logs or exports.
- Any email is sent without the user explicitly sending it from their provider.
- Backups, restore procedure, environment secrets or HTTPS settings have not been verified.

This checklist is not a penetration test and cannot prove the system is immune to attacks. A qualified security review is still required before a public multi-customer launch.
