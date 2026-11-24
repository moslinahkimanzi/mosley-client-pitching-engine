# MCAS commercial model and evidence scoring

## Website measurements

MCAS reports three independent dimensions, each from 0–100 where measurable:

1. **Technical Health** — public HTTP response, response type, page title, meta description, viewport metadata and primary heading. TLS/certificate validity is explicitly unknown in the current lightweight fetch.
2. **Business Readiness** — contact channels and owner-confirmed service details, conversion path, location/hours and real-device mobile testing. These require manual/owner-supplied evidence; a one-page HTML fetch cannot establish them.
3. **Commercial Opportunity** — a prioritisation index combining confirmed availability defects, limited technical findings, an absent discovery-listing URL (weak signal), public contact availability and owner-confirmed need.

### Credibility rules

- Every signal is reported as pass, issue or unknown. Unknown signals are excluded from the score denominator and lower evidence coverage instead of being silently marked as failures.
- A 200 response does not prove a site is secure, accessible, fast or commercially effective.
- A 403/429 may be access protection; it is not proof of a broken site.
- A search listing without a website URL is not proof that no website exists.
- The Commercial Opportunity score is not a probability of purchase, forecast of revenue or claim of buying intent.
- Scores should always be displayed with evidence, coverage, timestamp and methodology version. Re-run before sending a proposal.

## Proposed launch pricing (USD)

| Offer | Price | Included credits |
|---|---:|---:|
| Trial | Free once | 10 |
| Starter monthly | $12.00 / 30 days | 100 |
| Growth monthly | $29.00 / 30 days | 350 |
| Agency monthly | $79.00 / 30 days | 1,000 |
| Mini top-up | $5.00 one-time | 30 |
| Standard top-up | $15.00 one-time | 110 |
| Pro top-up | $49.00 one-time | 400 |

Credit costs:
- Research run: 5 credits
- Website audit: 2 credits
- AI draft: 2 credits
- Proposal generation (reserved for next metered feature): 3 credits
- Report export (reserved for next metered feature): 1 credit

These are proposed USD launch prices, not market-validated willingness-to-pay. Review actual API/search costs, provider fees, hosting, support, taxes/VAT, refunds and churn after a paid pilot. Keep the price table configurable rather than promising these rates permanently.

## Revenue target scenario

An illustrative USD 10,000 gross monthly revenue mix:
- 60 Agency accounts × $79 = $4,740
- 100 Growth accounts × $29 = $2,900
- 200 Starter accounts × $12 = $2,400
- Total = **$10,040 gross monthly billings**.

This is arithmetic, not a forecast. It excludes payment fees, taxes, refunds, failed renewals, discounts, infrastructure and support costs. Reaching this level requires customer acquisition, retention, product reliability and support capacity; it is not guaranteed by the pricing design.

## Payments and subscription lifecycle

- All catalogue prices and subscription/credit entitlements are denominated in USD.
- USD card checkout sends a USD transaction to Flutterwave.
- Kenyan M-Pesa checkout sends KES only. MCAS converts the USD list price using an explicitly configured USD/KES rate dated within the last three days; the rate and resulting KES amount are recorded on the payment. If the rate is absent or stale, M-Pesa checkout is disabled.
- The server records a pending transaction before checkout. A browser redirect never grants credits.
- The webhook secret hash is checked, then MCAS independently verifies transaction status, exact expected currency, amount, reference and purchase metadata before applying an entitlement.
- Provider transaction IDs and payment references are unique/idempotent. Credits are granted through an append-only ledger.
- Monthly subscriptions currently grant 30-day access and credits only after a verified payment. Renewal requires another payment in this release. Automatic M-Pesa debits are not enabled.
- Bank settlement currency and account eligibility are determined by provider merchant configuration and must be verified before launch; USD customer pricing does not guarantee USD bank settlement.

## Production prerequisites

1. Set `FLW_SECRET_KEY`, `FLW_SECRET_HASH` and the public HTTPS `MCAS_PUBLIC_URL` in the deployment secret manager. Never commit real secrets.
2. In Flutterwave's dashboard, set the approved Kenyan bank account as the settlement destination after KYC. Configure the exact webhook URL `/api/billing/flutterwave/webhook` in the provider dashboard and test signature/verification in sandbox.
3. Verify M-Pesa and card flows separately, including underpayment, wrong currency, duplicate webhook, delayed webhook, abandoned checkout, refunds and disputes.
4. Reconcile provider settlements daily. The ledger is not a substitute for provider statements or accounting.
5. Use PostgreSQL and a durable job queue before scaling beyond a small pilot; add invoice/tax handling, customer cancellation and refunds, dispute handling, alerts, backup/restore drills and external security review.
6. Do not enable live checkout until provider account/KYC, production credentials and a real payout account are approved.

## Payment and product boundaries

The current implementation does not read Gmail inboxes or send outreach messages. Payment webhooks are the only unauthenticated billing endpoint and require the configured provider signature hash plus independent server-side transaction verification.
