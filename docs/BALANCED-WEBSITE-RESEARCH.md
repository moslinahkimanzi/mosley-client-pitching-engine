# Balanced website-opportunity research

## User-facing contract

The Research command treats the selected number as a target **per category**:

1. `website_found`: verified business identity plus a first-party website linked to that identity and a bounded website check that did not confirm it as broken.
2. `no_website_found`: verified business identity, no first-party website discovered in the bounded Places + independent web search. This is not proof that no website exists anywhere.
3. `broken_website`: verified business identity plus an identity-linked first-party website returning HTTP 404 or 410 on two consecutive bounded checks.

The dashboard displays an equal-sized sample from each category. The balanced count is the minimum of the requested target and the available verified count in the smallest category. MCAS must never invent, duplicate, or relabel prospects to fill a category. A shortfall is returned explicitly.

## Discovery and verification (low-cost profile)

- One focused Serper Places query is made per run. The result is cached in memory for five minutes.
- The candidate budget is bounded by `min(30, max(12, target_per_group * 4))`; deduplication removes repeated name/address pairs.
- If a fetched first-party website title strongly matches the Places business name, MCAS can verify identity without an extra web-search request.
- Only uncertain identities (especially candidates with no listed website) trigger an independent Serper web corroboration search. Those search results may also identify a likely first-party website.
- Corroboration results are cached in memory for five minutes. Website checks use the existing SSRF-safe bounded fetcher.
- Unverified identities and ambiguous website states abstain from all three balanced categories.
- A quota/provider failure never becomes a positive verification result.

## Cost and speed

This profile uses one Places request per uncached research query, plus conditional web searches for uncertain candidates. It no longer runs three Places variants or automatically performs a web search for every candidate. A run is bounded by a maximum of 30 candidate records, and the requested target controls the candidate budget. The trade-off is that fewer candidates can mean a larger honest shortfall, especially for rare broken-website cases. Five-minute in-memory caching reduces repeat calls but is cleared when the server restarts.

## Important limitations

- Serper results are not a complete business registry or a complete crawl of the internet.
- "No website found" is always a bounded-search finding, never a global absence claim.
- HTTP 404/410 on two checks is evidence that the checked URL returned those statuses; it does not prove the business itself is closed.
- HTTP 401/403/429, 5xx, timeouts, redirects that cannot be safely followed, and other ambiguous outcomes are not labelled broken.
- A verified identity does not prove current trading, contact deliverability, consent to outreach, or buying intent.
- Balanced output is a sampling/display rule, not a claim that the market naturally contains equal proportions of these categories.
- Real-world reliability must be measured using independently reviewed samples in the Data Quality & Validation dashboard.

## Response fields

- `balance.requested_per_group`
- `balance.balanced_per_group`
- `balance.available_by_group`
- `balance.shortfalls`
- `balanced_results`: equal-sized selected records
- `additional_results`: reviewed candidates not selected into the balanced set
- `discovery_warnings`: non-fatal supplemental discovery errors
