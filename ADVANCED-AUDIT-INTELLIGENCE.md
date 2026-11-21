# Advanced Audit & Competitor Intelligence

## Website audit
The authenticated `POST /api/audit-website` endpoint now returns bounded static observations for:
- SEO metadata and document structure (title, description, canonical, Open Graph, JSON-LD, H1 and visible text volume).
- Mobile hints (viewport metadata).
- Accessibility hints (image alt attributes, language and heading start).
- Conversion hints (possible calls to action, forms/contact paths and internal navigation).
- Trust hints (privacy/contact links).
- Response-header observations (HTTPS, HSTS, CSP/frame-ancestors, nosniff and referrer policy).

The checks operate on a bounded HTML response and response headers fetched through the existing public-IP-pinned HTTP client. They do not execute JavaScript or active probes. A missing header/marker is a review item, not a confirmed vulnerability.

## Competitor intelligence
The authenticated `POST /api/competitor-intelligence` endpoint requires a prospect owned by the signed-in user and searches Serper Places for candidate businesses in the prospect's recorded market. It checks publicly listed competitor website URLs using the same constrained fetcher and returns comparison counts, source links and limited audit summaries.

Candidate listings are not verified direct competitors. Verify business identity, geography, category and all source details before using them in a proposal. Provider ratings can be incomplete or stale.

## Security boundaries
- No credentials are accepted from the browser for external providers; Serper remains server-configured.
- The existing SSRF controls are reused for all competitor website fetches.
- Prospect ownership is checked before the competitor lookup.
- Research routes have dedicated per-IP and per-session rate limits.
- Neither feature sends email, reads Gmail or changes a prospect's contact status.

## Known limits / next steps
- No Lighthouse or Core Web Vitals measurement (requires a separate isolated browser worker).
- No full WCAG conformance audit, crawler, sitemap/robots traversal, backlink/keyword rank data, malware scan or penetration test.
- No source-code ZIP audit or PDF report export in this feature branch.
- Competitor candidate matching is category/location search, not a validated market-share model.
- Before production, run the full test suite, test with real Serper credentials, inspect the browser UI and independently penetration-test the deployed environment.
