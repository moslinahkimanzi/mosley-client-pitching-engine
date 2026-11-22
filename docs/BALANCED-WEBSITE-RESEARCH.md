# MCAS automatic prospect and website verification

## Research stages

1. **Discovery:** one structured Serper Places request, cached in-process for five minutes.
2. **Direct website check:** when Places lists a website, MCAS fetches it using the existing SSRF-safe, DNS-pinned HTTP client. The checker validates redirect targets, blocks private/reserved addresses, allows only standard HTTP/HTTPS ports, and applies a short timeout and bounded response size.
3. **Independent corroboration:** if the listed website does not provide a strong identity match, or Places has no website URL, MCAS makes at most one focused Serper web search for that candidate.
4. **First-party domain candidate:** when no website is listed, a search result is considered a candidate only when its title/snippet matches the business name and locality and its domain contains a distinctive business-name token; social, directory, booking and review platforms are excluded.
5. **Website check:** a discovered first-party candidate is fetched with the same safe checker. A 404/410 is repeated once. Two 404/410 responses are required before the website is labelled broken.
6. **Persistence:** verification evidence, source URLs, website audit facts, check time and outcome are stored per workspace. New inconclusive candidates are saved as Unverified; they are not pitch-eligible.

## Identity evidence threshold

A structured Places record must include a usable business name and address, and the business must not be reported permanently closed. Automatic verification requires either:

- A safely fetched first-party website whose page title matches the business name and whose domain contains a distinctive business-name token; or
- At least two independent public web domains matching the business name and locality; or one matching public domain plus a Places phone/email that is corroborated in the matching public page text.

A single directory/search result is not enough. Social platforms and known aggregators do not independently verify identity. The evidence score is a deterministic rule-based index, not a statistical probability or measured accuracy percentage.

## Website condition labels

- `working`: the site responded with HTTP 2xx/3xx and basic homepage metadata checks did not find the selected gaps.
- `needs_improvement`: the site responded, but the bounded homepage check found a missing viewport declaration or meta description.
- `broken`: two checks returned HTTP 404 or 410, and the website domain is linked to the verified business.
- `access_restricted`: the site returned HTTP 401, 403 or 429. Its underlying condition remains unknown.
- `needs_review`: timeout, unsafe redirect, server error, fetch failure, or ambiguous result. Never treated as broken.
- `not_listed`: no likely first-party site was found in the bounded search. This is not proof that the business has no website.

These are lightweight homepage checks, not a full browser, accessibility, SEO, uptime history or penetration test.

## Latency and API cost controls

- Maximum eight candidate businesses per run.
- At most one Places request per uncached query.
- At most one independent web search per candidate.
- Website checks run with four concurrent workers.
- Each website check uses the existing five-second network timeout and bounded response body.
- A second website request is made only for an initial 404/410 result.
- Places results are cached in process for five minutes.

A run can still take longer when Serper or target websites are slow. Candidate processing is bounded; provider errors are preserved as inconclusive evidence rather than converted into false verification.

## Outreach safety

Automatic identity verification does not prove that the business is currently trading, that the listed contact belongs to an authorised decision-maker, that an email is deliverable, that marketing is permitted, or that the business wants a website. Only independently corroborated phone/email values are stored as verified contact fields. Review current trading and applicable marketing/opt-out requirements before outreach.

Research does not send email, create automatic Gmail drafts, or read incoming Gmail messages. Proposals and drafts remain approval-controlled.

## Accuracy measurement

CI tests prove expected software behaviour against fixtures; they do not establish real-world accuracy. Use the MCAS Data Quality review flow to independently label samples and calculate precision, recall, false-positive rates and website-state accuracy. Do not advertise a numeric accuracy claim until a sufficiently large, representative, independently reviewed sample supports it.
