# Balanced website-opportunity research

## User-facing contract

The Research command treats the selected number as a target **per category**:

1. `website_found`: verified business identity plus a first-party website linked to that identity and a bounded website check that did not confirm it as broken.
2. `no_website_found`: verified business identity, no first-party website discovered in the bounded Places + independent web search. This is not proof that no website exists anywhere.
3. `broken_website`: verified business identity plus an identity-linked first-party website returning HTTP 404 or 410 on two consecutive bounded checks.

The dashboard displays an equal-sized sample from each category. The balanced count is the minimum of the requested target and the available verified count in the smallest category. MCAS must never invent, duplicate, or relabel prospects to fill a category. A shortfall is returned explicitly.

## Discovery and verification

- Up to three Serper Places discovery queries are made: the base query, an independent-business variant, and a local-business variant.
- Each Places response requests up to 20 candidates; the merged candidate pool is capped at 60.
- Candidate deduplication uses normalized business name + address, preserving separately located branches.
- Each unique candidate receives an independent Serper web corroboration query.
- If Places does not list a website, MCAS looks for a likely first-party domain in the corroboration results. Directory, social, review and booking platforms are excluded; the domain must contain a distinctive business-name token and the result must match the business name and locality.
- The discovered domain is fetched using MCAS's existing SSRF-safe bounded fetcher.
- Unverified identities and ambiguous website states abstain from all three balanced categories.
- Provider errors do not turn into positive verification. Supplemental Places-query errors are surfaced as warnings; if independent corroboration fails for a candidate, that candidate is withheld.

## Cost and limits

A run can make up to three Places requests plus one web corroboration request per candidate (up to 60). A candidate website may require one or two bounded HTTP checks. This is materially more Serper usage than the old single Places query. Keep the target conservative until actual quota consumption and real-world yield are measured.

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
