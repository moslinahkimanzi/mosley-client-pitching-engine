# MCAS Google sign-in and administrator test lab

## Google OAuth setup

Google sign-in is the primary browser sign-in flow in this release. Google confirms the email identity through the OpenID Connect userinfo endpoint. MCAS accepts only a profile with a verified email and a subject identifier.

1. In Google Cloud Console, create or select a project.
2. Configure the OAuth consent screen and publish it according to the audience you intend to serve.
3. Create an OAuth client ID of type **Web application**.
4. Add the exact authorised redirect URI:
   `https://YOUR_PUBLIC_DOMAIN/api/auth/google/callback`
   For local development only, use:
   `http://127.0.0.1:8000/api/auth/google/callback`
5. Put the Client ID, Client Secret and exact redirect URI in the server-side environment:
   - `GOOGLE_OAUTH_CLIENT_ID`
   - `GOOGLE_OAUTH_CLIENT_SECRET`
   - `GOOGLE_OAUTH_REDIRECT_URI`
6. Keep the client secret on the server. Never put it in index.html, assets/app.js, a public repository, browser storage or customer-visible settings.
7. Set `MCAS_ADMIN_EMAILS` to the exact administrator email address(es), and configure a random `MCAS_ADMIN_BOOTSTRAP_TOKEN` of at least 32 characters before first admin account creation.
8. Configure the existing administrator MFA encryption key and production MFA requirements. A newly-created administrator must enrol an authenticator before using admin endpoints.

The OAuth start flow uses a one-time state value stored server-side and a SameSite=Lax, HttpOnly state cookie. The callback exchanges the authorization code server-side and requests the Google OpenID Connect userinfo endpoint. Existing accounts with the same verified Google email are linked to that email identity and marked verified.

## Legacy email/password accounts

The browser UI no longer exposes the email/password or email-verification workflow. Existing accounts should sign in once with the same Google-verified email to activate the Google sign-in path. Legacy API routes and database columns are retained in this release for backward compatibility and existing test fixtures; they are not linked from the browser UI. A later migration should remove them after operators confirm all active accounts have migrated.

## Administrator bootstrap behaviour

The bootstrap field is hidden for ordinary customer email addresses. The browser asks a rate-limited endpoint whether the typed address is a configured administrator address whose account does not yet exist. The server independently validates the bootstrap token before authorising creation. An email typed into the form does not determine the final identity: the Google-verified callback email is authoritative.

The administrator bootstrap token is required when creating the configured administrator account for the first time. Administrator maintenance endpoints remain protected by server-side configured-email checks and administrator TOTP MFA in production.

## Website evidence and opportunity labels

- A verified identity is not proof of ownership, current trading, marketing consent or buying intent.
- A website opportunity requires a verified business identity and an identity-linked technical issue supported by the fetched first-party homepage.
- A broken website requires two 404/410 responses and an identity-linked domain.
- No website found means a bounded public search did not find a likely first-party website for a verified business. It is not proof that no website exists anywhere.
- Timeout, access restriction, unsafe redirect and server errors remain inconclusive, not broken.
- Only supported homepage observations (page title, meta description, primary heading, viewport metadata, image alternative text, contact path and obvious action elements) can qualify as concrete technical opportunities in this workflow.

## Advanced website audit scope

The audit accepts a public domain with or without an http/https prefix and uses the existing DNS-pinned SSRF-safe fetcher. It inspects one bounded HTML response and response headers. It does not render JavaScript, crawl all routes, submit forms, log in, measure real-user Core Web Vitals, test checkout flows, run malware scanning or exploit vulnerabilities. A site may block automated requests or require JavaScript; those cases need a browser-based staging test and remain outside this static audit.

## Administrator feature test lab

The Maintenance tab provides a read-only staging-site inspection and manual acceptance checklist for an AI-suggested feature. It is deliberately not an arbitrary code runner. Never execute AI-generated code against production data. Use a separate staging deployment, synthetic accounts and test data; manually run the acceptance checklist, inspect logs and browser behaviour, and obtain human release approval.

## Clipboard behaviour

The email studio copy button copies the subject and body currently in the editor. It works for both the deterministic MCAS draft and the connected AI-generated email because both populate the same editable field. The reply assistant has its own copy button. Clipboard access requires a secure context (HTTPS or localhost) and browser permission.

## USD estimates

The website advisor displays USD equivalents converted from the existing Kenya-market KES estimate bands using an illustrative KES 130/USD assumption. This is not a live FX quote. Update the conversion assumption before relying on it commercially, and confirm scope and local pricing before issuing a proposal.
