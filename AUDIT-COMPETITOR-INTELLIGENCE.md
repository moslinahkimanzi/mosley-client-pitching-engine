# Audit & Competitor Intelligence workspace

MCAS exposes a dedicated **Audit & Competitor Intelligence** workspace tab.

## Advanced website audit

- Authenticated endpoint: `POST /api/audit-website`.
- Performs a bounded same-host crawl (1–15 pages) using the existing SSRF-constrained `safe_site_fetch`.
- Checks public HTTP response, page metadata, accessibility signals detectable in static HTML, mixed-content references, and response security headers.
- Can be linked to a saved prospect. When a prospect is selected, the submitted URL must match that prospect's saved website; the existing audit storage/status workflow is used.
- Findings are observations for human review, not proof of exploitable vulnerabilities.

## Competitor intelligence

- Authenticated endpoint: `POST /api/competitor-intelligence`.
- Requires a prospect owned by the signed-in workspace and a recorded market/location.
- Searches Serper Places for up to eight candidate businesses in the selected category and market.
- Checks the target prospect's listed website and candidate websites using the same safe fetcher and a maximum of three same-host pages per site.
- Returns candidate business names, categories, provider-listed addresses/websites/ratings, source links, website response state, and limited audit summaries.
- Uses a separate shared rate-limit bucket (five requests per minute).

## Important limitations

- Serper Places results are candidate businesses, not verified direct competitors.
- Provider addresses, websites, ratings and review counts may be missing, stale or inaccurate; verify them independently.
- A provider not listing a website does not prove the business has no website.
- Static HTML checks do not execute JavaScript or test interactive browser behaviour. They are not Lighthouse/Core Web Vitals, a full WCAG audit, malware scan, penetration test, or security certification.
- The endpoint does not save competitor records, create proposals, create outreach drafts, read Gmail, or contact businesses.
- No automatic production changes are made by this feature.
