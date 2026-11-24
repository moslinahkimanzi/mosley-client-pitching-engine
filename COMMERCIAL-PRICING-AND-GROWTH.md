# MCAS commercial pricing and growth model

**Status:** proposed launch pricing for testing. These are MCAS recommendations, not guarantees of market demand or income.

## 1. Keep two businesses and revenue streams separate

MCAS operator services are delivered to an individual business and are generally one-off projects or monthly retainers. MCAS SaaS subscriptions and usage credits are payments for platform access. They require separate contracts, invoices, terms, revenue reporting and support policies.

## 2. Done-for-client website services (Kenya launch prices)

All prices are indicative KES starting ranges. Final written quotations depend on scope, content readiness, integrations, page count, revisions, ownership, hosting and support. Third-party subscriptions, domain registration, hosting, paid stock assets, payment gateway fees and taxes are shown separately.

| Service | Recommended price | Typical scope |
|---|---:|---|
| Technical website check and prioritised report | KES 3,500–8,000 | Bounded public-page audit, evidence, severity, recommendations and manual review; not a penetration test |
| Small website repair sprint | KES 5,000–20,000 | Agreed, limited fixes such as broken routes, metadata, form/CTA or layout corrections |
| One-page landing page | KES 15,000–25,000 | One conversion-focused page, mobile-first layout, enquiry/WhatsApp action, basic metadata |
| Starter business website | KES 25,000–45,000 | Typically 3–5 pages, responsive layout, contact path, basic on-page SEO |
| Professional business website | KES 50,000–95,000 | Typically 6–12 pages, custom design, content structure, forms, analytics setup subject to consent |
| Small e-commerce website | KES 70,000–150,000 | Catalogue, cart/checkout, order workflow and agreed payment integration |
| Custom portal / workflow system | From KES 150,000 | Discovery and written scope required; complex software is quoted separately |
| Website care and maintenance | KES 4,000–12,000/month | Agreed updates, backup checks, uptime checks and limited support; define hours and exclusions |
| Local SEO implementation / monthly work | KES 8,000–25,000/month | Agreed technical/on-page tasks and reporting; no ranking guarantees |

A benchmark review of Kenyan providers published in 2026 shows broad price dispersion: simple business websites are often advertised around KES 15,000–40,000, larger company sites around KES 35,000–120,000 and small e-commerce builds around KES 50,000–150,000. The proposed MCAS service ranges sit within or near those published bands but are not a statistical survey. Obtain at least three comparable quotes before changing prices. Example published guides: https://wfw.co.ke/blog/how-much-does-a-website-cost-in-kenya and https://gilvon.com/pricing.

### Scope and payment terms for client projects

- Provide a written scope, deliverables, exclusions, acceptance criteria, timeline and change-request rate before collecting a deposit.
- Suggested milestone schedule: 50% to book/start, 30% after staging review, 20% before production handover. Adjust for small jobs and written customer agreement.
- State who owns the domain, hosting account, source code, content and licences. Prefer client-owned domain/hosting accounts.
- List recurring hosting, domain, plugin, email, payment provider and maintenance costs separately.
- Do not describe a static automated audit as a penetration test, full accessibility certification, Lighthouse report or security certification.
- Do not promise SEO rankings, leads, conversions, revenue or delivery dates before scope and dependencies are agreed.
- Use a written acceptance sign-off and retain evidence of customer approval.

## 3. MCAS SaaS subscriptions

Launch in KES for the Kenyan market. USD reference prices are proposed international list prices; the first billing implementation accepts KES checkout only until the merchant account's international currency settlement and pricing are tested.

| Plan | KES / month | USD reference / month | Included monthly credits | Seats | Suggested fit |
|---|---:|---:|---:|---:|---|
| Free | KES 0 | $0 | 20 | 1 | Product evaluation with conservative limits |
| Starter | KES 2,500 | $19 | 150 | 1 | Independent developer / small operator |
| Growth | KES 6,500 | $49 | 500 | 3 | Active freelancer / small studio |
| Agency | KES 16,900 | $129 | 1,500 | 5 | Small agency / team workflow |
| Business | Custom | Custom | Contracted | Contracted | Larger usage, support or security requirements |

The KES and USD prices are separately chosen price points, not a claim that they are an exact current FX conversion. Review local willingness to pay, usage costs, churn, gateway fees and support burden after a controlled pilot.

## 4. Prepaid credit packs

| Pack | KES price | Credits |
|---|---:|---:|
| Small | KES 1,500 | 100 |
| Standard | KES 6,500 | 500 |
| Studio | KES 13,000 | 1,200 |

Purchased credits are separate from subscription allowance. The application spends monthly allowance first, then purchased credits. The initial product design keeps purchased balances non-transferable. Publish a clear refund, expiry and account-closure policy before enabling production sales; legal/accounting review is required before final terms.

## 5. Suggested usage-credit schedule

| Action | Credits |
|---|---:|
| Serper prospect research run, up to 6 results | 5 |
| Additional prospect capacity above 6 (per up to 2 results) | +1 |
| Fresh business identity re-check | 3 |
| Website audit, up to 5 pages | 3 |
| Website audit, 6–10 pages | 5 |
| Website audit, 11–15 pages | 7 |
| Competitor scan, up to 3 candidates | 6 |
| Competitor scan, 4–5 candidates | 8 |
| Competitor scan, 6–8 candidates | 11 |
| AI email, reply or proposal generation | 1 |

The credit schedule is a proposed packaging rule, not a measure of exact third-party cost. Monitor Serper, AI provider, hosting, support, refunds and abuse costs. Reprice if the included usage is unprofitable. A request that fails before a result is returned should not consume credits; the service should refund its reserved credits on an exception.

## 6. $10,000/month target: transparent scenarios

This is a gross recurring-revenue goal, not a forecast or guarantee. It excludes payment-processing fees, refunds, taxes, hosting, Serper/AI consumption, staff, support, marketing and other expenses.

Illustrative subscription-only mixes at the proposed USD list prices:

- 205 Growth accounts × $49 = $10,045 gross MRR.
- 78 Agency accounts × $129 = $10,062 gross MRR.
- 100 Growth accounts × $49 + 40 Agency accounts × $129 = $10,060 gross MRR.

One-time credit packs and website projects can add revenue, but should not be counted as MRR. Track active paying subscribers, monthly recurring revenue, churn, failed renewals, average revenue per account, gross margin after variable API costs, support time per account, refund/chargeback rate and customer acquisition cost.

A realistic path is to validate the product with a small paying cohort, prove retention and gross margin, then increase acquisition. Do not spend to acquire large numbers of users until the product's repeat use and support requirements are understood.

## 7. Launch gates

1. Test the complete checkout, webhook, verification, idempotency, credit grant and downgrade flow in the provider sandbox.
2. Obtain merchant KYC approval and confirm payment methods, chargebacks, settlement timing, fees and account eligibility with the provider.
3. Publish service terms, SaaS terms, privacy notice, cancellation/refund policy and credit terms.
4. Assess Kenya data protection obligations and registration with ODPC where applicable. See https://www.odpc.go.ke/data-protection-compliance/index.html.
5. Use a production database, tested backups, monitoring and independent security review before accepting meaningful customer volume.
6. Do not represent test or pending payments as paid. Only a server-verified transaction activates paid value.
