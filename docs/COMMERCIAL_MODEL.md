# MCAS pricing, billing and revenue assumptions

## SaaS prices

| Product | Price | Credits |
|---|---:|---:|
| Free allowance | KES 0 | 20 per 30-day allowance period |
| Starter | USD 12 / 30 days | 100 per paid period |
| Growth | USD 29 / 30 days | 350 per paid period |
| Agency | USD 79 / 30 days | 1,000 per paid period |
| Mini top-up | USD 5 one-time | 30 |
| Standard top-up | USD 15 one-time | 110 |
| Pro top-up | USD 49 one-time | 400 |

The catalogue is configured server-side. The browser submits a product code, never a payment amount. Legacy KES orders and their balances remain readable and verifiable; new orders store their USD list price and the provider currency/amount separately.

## Actual credit metering

These values must remain aligned with the deductions in `backend.billing`:

- Research run: 5 credits.
- Business recheck: 3 credits.
- Website audit: 3 credits for 1–5 pages, 5 for 6–10 pages, and 7 for 11–15 pages.
- Competitor analysis: 6 credits for 1–3 competitors, 8 for 4–5, and 11 for 6–8.
- AI generation: 1 credit.

The ledger is the record of credit grants and deductions. Monthly credits are consumed before purchased credits. Do not describe an unmetered feature as a paid credit deduction.

## Currency and payment behaviour

- All new plan and top-up list prices are denominated in USD.
- Card checkout sends the USD price to Flutterwave in USD.
- Kenyan M-Pesa checkout is sent in KES. MCAS converts the USD list price using `MCAS_USD_KES_RATE` and `MCAS_USD_KES_RATE_DATE`.
- The M-Pesa rate is operator-maintained, displayed with its date, and rejected if it is missing, future-dated, invalid or older than three days. This is not a live FX feed. The operator must update the rate from a reliable source and record the date.
- The server stores a pending order before creating checkout. A browser redirect never grants credits or plan access.
- The webhook validates Flutterwave's HMAC-SHA256 `flutterwave-signature` against the raw request body. The older `verif-hash` header is accepted only for backward compatibility.
- MCAS independently verifies the transaction with Flutterwave and checks successful status, the server-generated transaction reference, exact expected currency and exact expected amount. Metadata is checked when the provider includes it; transaction metadata may be null in Flutterwave's verification response.
- A payment is applied once. Provider transaction IDs are unique, order state is checked transactionally, and credit changes are written to the credit ledger.
- Paid plans provide a 30-day period. Renewal is customer-initiated; automatic recurring card or M-Pesa debits are not enabled.
- An overpayment or mismatched payment is not silently converted into credits. It remains unresolved for manual reconciliation/refund.

## Illustrative USD 10,000 gross monthly target

One possible arithmetic mix is:

- 60 Agency subscriptions × USD 79 = USD 4,740.
- 100 Growth subscriptions × USD 29 = USD 2,900.
- 200 Starter subscriptions × USD 12 = USD 2,400.
- Total = **USD 10,040 gross monthly billings**.

This is a target scenario, not a forecast or guarantee. It excludes payment fees, taxes, refunds, failed renewals, discounts, hosting, AI/search costs, support, churn and customer acquisition costs. Validate willingness to pay and unit economics with a small paid pilot before scaling.

## Launch and settlement prerequisites

1. Keep `MCAS_BILLING_ENABLED=false` until test-mode card and M-Pesa flows have passed.
2. Configure test/live `FLW_SECRET_KEY`, a strong `FLW_SECRET_HASH`, and a public HTTPS `MCAS_PUBLIC_URL` only in the server secret manager. Never commit real credentials.
3. Configure the Flutterwave webhook URL as `https://YOUR_PUBLIC_HOST/api/billing/flutterwave/webhook` and enable webhook retries.
4. Test successful, failed, delayed, duplicate, wrong-reference, wrong-currency, wrong-amount, abandoned and refund/dispute scenarios.
5. Complete provider KYC and confirm the approved bank/M-Pesa settlement destination and settlement currency with Flutterwave. USD customer pricing does not guarantee USD bank settlement.
6. Reconcile provider statements against MCAS orders and the credit ledger. Add refund, cancellation, tax/invoice, dispute and customer-support procedures before public launch.
7. Before scaling beyond a small pilot, move from SQLite to managed PostgreSQL, use a durable job queue, centralised rate limiting, monitoring, tested backups and an independent security review.

## Boundaries

- Payment confirmation comes only from server-side provider verification, not a return URL or browser state.
- Gmail integration remains draft-only; MCAS does not read incoming mail or send outreach messages.
- These controls reduce risk but do not replace sandbox testing, merchant approval, operational reconciliation or an independent security assessment.
