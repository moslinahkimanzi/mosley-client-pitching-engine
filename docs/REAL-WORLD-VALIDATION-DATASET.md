# MCAS real-world prospect validation dataset

## Purpose

This dataset measures how well MCAS's research predictions agree with independent, human-reviewed ground truth. It is a quality-control sample, not a public business directory and not a guarantee that every prospect is accurate.

Each research candidate is captured before the workflow decides whether it is safe to save as a prospect. This includes identity-verification failures and provider outages. Predictions are immutable snapshots for evaluation; a reviewer label does not rewrite the original prediction.

## Website categories shown to users

- **Website found**: MCAS has a public website URL and evidence linking the domain/page to the business.
- **No website found in bounded search**: MCAS did not receive a business website URL in the structured listing during that research run. This is not proof that the business has no website anywhere.
- **Unknown**: the business identity, search coverage, or website-to-business relationship was not strong enough to classify.

Manual CRM records with no website URL remain **Unknown** unless independently researched. An empty URL must never be treated as proof of website absence.

## Ground-truth review procedure

For every candidate selected for validation:

1. Independently confirm that the named business exists (or that the listing is a false identity / wrong entity).
2. Check the business's own website, if one can be found, and record the actual public URL in the evidence note.
3. Check the website's current response/status using a browser and, where appropriate, a second independent check. Distinguish a website outage, access restriction, and a truly unavailable page.
4. Independently check whether the listed email or phone is published by the business or a trustworthy current source. Accuracy does not establish consent or permission to market.
5. Record source URLs, date checked, what was observed, and any ambiguity in the evidence field.
6. If evidence is insufficient, leave the label Unknown / Not assessed. Do not guess merely to fill the dataset.

Prefer the business's own website, official registries, verified official social profiles only as supplementary contact evidence, or authoritative local directories. Do not use the same Serper result that MCAS used as the only ground-truth source. Do not enter private personal contact details or sensitive information.

## Labels and metrics

### Identity verification
- Ground truth: exists / does_not_exist / unknown.
- MCAS prediction: verified / not verified.
- Report: true positives, false positives, false negatives, true negatives, accuracy, precision, recall, specificity, false-positive rate and false-negative rate.

### Website presence
- Ground truth: website_found / no_website_found / unknown.
- MCAS prediction: website_found / no_website_found / unknown.
- "No website found" is limited to the search coverage of the recorded run. It is not an ontological claim that no site exists.

### Website status
- Ground truth and prediction: working / broken / needs_improvement / access_restricted.
- Exact-match accuracy is reported only for labelled and comparable records. A website status that could not be assessed is not counted as correct.

### Contact data
- Email and phone are reviewed independently as correct / incorrect / not checked.
- Accuracy denominator includes only values explicitly checked by a reviewer. Missing contact values and unreviewed values are shown separately.
- Accuracy means the value matches an independent public business source at the review time; it does not measure deliverability, ownership, consent or marketing legality.

All metrics are descriptive of the labelled samples in the signed-in workspace. Unknown labels and abstained predictions are reported separately rather than silently counted as correct.

## Stratification and sampling

Review samples across each supported industry and more than one location. Avoid collecting only easy or high-scoring cases. Include:
- candidates MCAS verified and candidates it rejected;
- records with and without a listed website;
- working, unavailable, restricted and inconclusive websites;
- businesses with and without public email/phone values;
- multiple neighbourhoods, cities, counties and countries as the product expands.

The dashboard reports overall, by-industry and by-location metrics. For a fairer comparison, keep a time-stamped evaluation cohort and avoid tuning rules on the same records used for final evaluation. Build a separate holdout sample before changing verification thresholds.

## Suggested minimum launch evidence

These are proposed internal release gates, not universal statistical guarantees:
- At least 100 independently reviewed identity samples overall.
- At least 30 reviewed samples in each industry/location segment before making segment-specific claims.
- Report confidence intervals (not yet implemented in the dashboard) before publishing accuracy claims.
- Investigate every false positive in identity verification and every incorrect website/contact claim.
- Keep an explicit Unknown / abstention rate; do not optimize accuracy by hiding hard cases.
- Re-run the holdout set after changes to Serper query design, name matching, website fetch logic or provider configuration.

A sample of 3–10 records is useful for smoke testing only, not evidence of commercial-grade accuracy.

## Privacy and access

Validation samples are associated with the user who initiated the research. Read, review and metrics endpoints filter by the authenticated user ID. Contact values are held in that user's workspace only to permit accuracy review; they are not shown in the metrics aggregate. Account deletion cascades the validation samples. Do not copy customer or prospect personal data into a shared benchmark without a separate lawful basis, notice, access control and retention policy.

## Limitations

- Serper Places and web results are provider-sourced and can be stale, incomplete or duplicated.
- A public web page matching a name and locality does not prove legal identity or current trading.
- Website checks are point-in-time observations and may be affected by CDN rules, geoblocking, bot protection, transient outages and redirects.
- A website's HTTP response does not measure full functionality, security, SEO, accessibility, performance or user experience.
- A correct-looking email/phone may be stale or undeliverable.
- Metrics on a convenience sample do not automatically generalize to all businesses, geographies or industries.
