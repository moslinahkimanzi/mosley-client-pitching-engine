# MCAS prospect verification and pitch qualification

## Separate decisions

MCAS records three distinct decisions. They must not be collapsed into one score:

1. **Discovery** — Serper Places returned a candidate business listing.
2. **Identity corroboration** — the listing has a usable business name and address, plus either a matching title on its listed business website or an independent public web result that matches both the business name and locality.
3. **Website opportunity qualification** — the identity is corroborated and MCAS observed a reproducible, identity-linked website issue.

An opportunity score is a sorting heuristic only. It is not a probability, buying-intent score, credit score, or proof that the business wants a website.

## Automatic verification rules

- A Places result alone is not enough.
- Ordinary web results are never silently substituted for structured Places business records.
- Social-media profiles, Google/Maps pages and search-provider pages do not count as independent identity corroboration.
- Name matching normalises accents, punctuation and common company suffixes.
- A public corroborating result must match the business name and at least one locality token from the search location or listing address.
- Missing address, mismatched name/locality, provider failure, and permanently closed status prevent an automatic verified decision.
- The evidence score is a deterministic rule-based score, not a calibrated probability.
- Contact email and phone values from a Places listing remain provider-listed until separately corroborated. Only an independently corroborated email may be placed into a Gmail draft recipient field.

## Website opportunity rules

- A missing website link is **not** evidence that a business has no website. MCAS saves the identity if corroborated but does not qualify a new-website pitch from that fact alone.
- HTTP 404/410 must be observed twice in bounded checks before the listed URL is described as unavailable.
- HTTP 5xx, timeouts, blocked requests, 401/403/429, redirects that cannot be safely followed, and non-HTML responses are not described as confirmed broken websites.
- Homepage metadata gaps qualify only when the listed website itself is identity-linked by its title. These are limited static observations, not a complete SEO, accessibility, performance, browser, malware, or penetration audit.
- A verified identity with no material website issue is retained as a verified business but has `pitch_eligible=0`.

## Sales-material controls

- Uncorroborated candidates are returned as withheld research results; they are not inserted into the CRM.
- A verified business is saved with `research_origin=serper_places`, verification evidence, evidence score, and verification timestamp.
- MCAS automatically creates a proposal and pending-approval email draft only when `pitch_eligible=1`.
- Backend draft, proposal, and website-builder-prompt endpoints enforce the pitch gate for research-origin prospects; UI hiding alone is not a security control.
- No email is sent automatically. Gmail integration creates drafts only.
- Manual CRM leads retain the existing user-managed workflow; manual status changes are not represented as automated verification.

## API quota and operating cost

Each Places candidate checked in a research run triggers one additional candidate-specific Serper web search for independent corroboration. A run of 6 candidates can therefore use one Places request plus up to 6 web-search requests, with additional website requests performed by MCAS directly against the listed public sites. Check the current Serper plan and quota before increasing batch sizes.

## What this does not prove

Automated corroboration does not establish legal identity, beneficial ownership, that the business is currently trading, contact deliverability, marketing consent or lawful basis, decision-maker identity, budget, buying intent, or a willingness to purchase. Users must still review the evidence and comply with applicable direct-marketing, privacy, and opt-out rules before sending a draft.

## Quality gates

The test suite covers normalised name matching, address and locality corroboration, rejection of uncorroborated and social-only records, closed-business rejection, missing-website non-qualification, repeated 404/410 requirements, homepage metadata identity linkage, and API-level prevention of drafts/proposals for non-qualified research prospects.

Before commercial launch, add a labelled validation set from target markets and measure precision, false-positive rate, false-negative rate, contact-data accuracy, website-state accuracy, and drift by industry and geography. Do not claim a universal accuracy percentage until this evaluation has been run and independently reviewed.
