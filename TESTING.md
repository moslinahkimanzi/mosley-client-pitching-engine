# MCAS pre-publication test plan

For the current research-completion build, test branch `feature/mcas-research-completion` (it includes the prerequisite feature branches). The work is still an open draft pull request and is not in `main`; do not deploy it publicly until the changes are reviewed, merged and the production checklist is complete. Preserve your local `.env` and `data/mcas.db` when switching branches; never run `git reset --hard` or delete local data to update the build.

## A. Automated checks

Run these from the project root with the virtual environment active:

    python -m compileall -q backend tests
    python -m unittest discover -s tests -v
    node --check assets/app.js
    pip-audit -r requirements.txt

All commands should exit successfully. Resolve every dependency advisory before publishing. GitHub Actions runs the same checks on branch pushes and pull requests.

## B. Start locally

    source .venv/bin/activate
    set -a
    source .env
    set +a
    uvicorn backend.app:app --host 127.0.0.1 --port 8000

Open http://localhost:8000 in Firefox. Use the same hostname consistently for browser and OAuth testing. Health endpoint: http://localhost:8000/api/health.

## C. Functional walkthrough

0. Open Website advisor. Generate recommendations for at least three business types (for example, restaurant, professional services and retail). Check that the recommended site type, pages, features, quality standards and improvement roadmap change with the selected inputs. Confirm the output is described as guidance, not a verified audit or guaranteed outcome.
0a. Open Research → Research command centre. Search a named town or city (for example, Nairobi), choose a category and start with 3 results. Confirm results become unverified prospects and each new prospect gets a saved website plan, proposal and pending email draft. Confirm a missing website URL is labelled as "not listed", not proof of no website. Verify OpenStreetMap attribution appears.
0b. If Gmail is configured and an OpenStreetMap record contains a valid public contact email, confirm MCAS creates a Gmail draft only. Check Gmail Drafts; confirm nothing was sent. If no public email is listed, confirm the draft remains in MCAS.
0c. Mark a test prospect as Client accepted / Won. Confirm Generate AI-builder prompt appears, and that the prompt includes the business category, proposed pages, features, quality and instructions not to fabricate content.
0d. In Reply Assistant, manually paste a sample customer message and optionally enter the customer's email address. Save it, then create a Gmail draft from Saved Drafts. Confirm the generated reply is automatically saved to MCAS as pending approval. Confirm MCAS never asks for or reads inbox contents.
0a. Open Research → Research command centre. Search a named town or city (for example, Nairobi), choose a category and start with 3 results. Confirm results become unverified prospects and each new prospect gets a saved website plan, proposal and pending email draft. Confirm a missing website URL is labelled as "not listed", not proof of no website. Verify OpenStreetMap attribution appears.
0b. If Gmail is configured and an OpenStreetMap record contains a valid public contact email, confirm MCAS creates a Gmail draft only. Check Gmail Drafts; confirm nothing was sent. If no public email is listed, confirm the draft remains in MCAS.
0c. Mark a test prospect as Client accepted / Won. Confirm Generate AI-builder prompt appears, and that the prompt includes the business category, proposed pages, features, quality and instructions not to fabricate content.
0d. In Reply Assistant, manually paste a sample customer message and optionally enter the customer's email address. Save it, then create a Gmail draft from Saved Drafts. Confirm MCAS never asks for or reads inbox contents.

1. Register a fresh test account with a unique email and a strong, unique password.
2. Add a test business with website, source URL, evidence and contact email. Confirm dashboard counts update.
3. Change its status to Verified. Mark it Do Not Contact and try generating an email. MCAS should block the outreach draft.
4. Remove Do Not Contact for the test record. Generate a cold email and save it. Confirm it appears in Saved Drafts and the pending-draft count increases.
5. Stop and restart the server, sign in again and verify prospects and drafts still exist.
6. Add a follow-up task, mark it complete and verify the status.
7. Generate a proposal structure, edit it and save it.
8. Export workspace data. Store the downloaded JSON securely; it contains customer data.
9. Paste a sample customer reply into Reply Assistant. Verify opt-out language produces a response that respects the request.
10. Run a quick check against a website you control. Check HTTP status/title/viewport results; this is not a full audit.
11. Search without a Brave key. The interface should explain that search is not configured, not invent results.
12. Open a second Firefox private window, register another test user and confirm that user cannot see the first user's leads, drafts or follow-ups.
13. Put harmless markup such as <img src=x onerror=alert(1)> in a prospect name/evidence field. It should display as text, not execute.
14. Open DevTools → Network. Confirm /assets/app.js and same-origin /api/* calls load. Session cookies must not be stored in localStorage.

## D. Security negative tests

Automated tests cover unauthenticated access (401), mutation without CSRF (403), tenant separation, private IPv4 rejection, salted password hashes, CSRF tamper detection and baseline security headers.

Manual website-check tests: try http://127.0.0.1, http://localhost, a private LAN address, a non-standard port and an HTTPS URL redirecting to HTTP. These should be blocked. Do not test against third parties without permission.

## E. Optional integrations

- Brave Search: configure BRAVE_SEARCH_API_KEY on the server, restart and test a discovery query. Verify source links and facts yourself.
- AI: configure AI_API_BASE_URL, AI_API_KEY and AI_MODEL on the server. Test email, reply and proposal drafting. Treat every generated claim as untrusted until verified.
- Gmail: configure Google OAuth client ID/secret/redirect URI and MCAS_ENCRYPTION_KEY. Connect a test Gmail account, save a draft with a recipient and click Create Gmail draft. Confirm it appears in Gmail Drafts and has not been sent. Also test auto-draft-on-research using a safe test address. Verify no inbox-reading scope is requested and there are no message-list/get/send application routes. Test disconnect.
- Provider tests may incur usage charges. Keep credentials on the server, never in the repository or browser.

## F. Stop before publishing if

- Any automated check fails or pip-audit reports an unresolved advisory.
- Data appears in the wrong account.
- A mutation works without a valid CSRF token.
- User-entered text executes as HTML/JavaScript.
- Website checks reach localhost, private IP ranges or metadata services.
- OAuth tokens appear in browser storage, logs or exports.
- Any email is sent without the user explicitly sending it from their provider.
- Backups, restore procedure, environment secrets or HTTPS settings have not been verified.

This checklist is not a penetration test and cannot prove the system is immune to attacks. A qualified security review is still required before a public multi-customer launch.

## Additional research completion checks

- Research a known local area using a town/city/neighbourhood name; verify the resolved place label and bounding-box results.
- Verify a broad country-level query is rejected and the user is asked for a smaller area.
- Verify each prospect displays an opportunity-priority score and its reasons; confirm it is described as a research heuristic, not buying intent.
- Verify the result summary shows reviewed count, newly saved count and highest score.
- Verify a repeated research run uses cached business results but still returns a resolved place label.
- Verify map data with no website tag is described as "not listed", never "no website".
- Verify public website checks are labelled lightweight and do not claim a complete SEO/performance/accessibility/security audit.
