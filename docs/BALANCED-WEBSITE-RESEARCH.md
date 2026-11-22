# MCAS research: fast, evidence-first discovery

## Research behaviour

The Research command searches for businesses in one flat results list. There are no three-way result buckets, no equal-count target, and no wait for a rare category such as confirmed broken websites to be filled.

The selected maximum is the overall number of verified businesses MCAS aims to collect in a run. It stops once that number is reached or the bounded Places candidate pool is exhausted.

## Discovery and verification

- One focused Serper Places query is used per uncached research run. Places responses are cached in memory for five minutes.
- The candidate pool is bounded to at most 20 records. Its size scales with the requested overall verified-business target.
- A candidate with a listed first-party website can be identity-verified without an extra web search when the safely fetched page title strongly matches the business name.
- MCAS uses an independent Serper web search only when the Places result and checked website do not provide sufficient identity evidence.
- If the web search discovers a likely first-party website, MCAS fetches it using the existing SSRF-safe checker.
- A website is marked broken only after two checks return HTTP 404 or 410 and its domain is linked to the verified business. Timeouts, access restrictions, server errors, and ambiguous redirects are not treated as broken.
- Unverified candidates remain visible in the research results with their reasons, but are not saved as verified CRM prospects and do not generate outreach proposals or drafts.

## Cost and speed

One Places query is made per uncached search. Independent web queries are conditional, not automatic for every candidate. Five-minute in-memory caching reduces repeated requests for the same query during the same server process. The candidate cap and overall verified-business stop condition prevent runs from continuing indefinitely to fill artificial categories.

The API response includes research_limits, which reports the candidate budget, Places request/cache state, and number of independent web searches.

## Credibility and limitations

- Serper is a discovery provider, not a complete registry of every operating business.
- A verified identity means the Places listing was corroborated by a matching public page or a matching first-party website title. It does not prove current trading, ownership, email deliverability, consent to contact, or buying intent.
- A missing website URL in the Places listing is not proof that the business has no website.
- Website condition labels describe the bounded checks MCAS performed; they are not a full browser, uptime, accessibility, SEO or penetration test.
- Review evidence and contact details before outreach and respect applicable marketing and opt-out rules.
- Gmail remains draft-only. MCAS does not read incoming messages or send outreach automatically.
