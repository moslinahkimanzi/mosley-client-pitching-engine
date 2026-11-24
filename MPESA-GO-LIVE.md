# M-PESA merchant collection and MCAS payment integration

This document describes the safe route for collecting MCAS subscription payments in Kenya. **Live checkout is not implemented or enabled in this code line.** The existing billing endpoint deliberately reports billing disabled. Do not accept customer money until the merchant account, Daraja production access, callback verification, subscription entitlement logic, reconciliation and refund handling have been tested.

## 1. Choose the Safaricom merchant collection product

For recurring SaaS subscriptions, ask Safaricom which product is appropriate for your registered business and expected transaction pattern:

- **Business Paybill:** usually the clearer fit when each customer should enter an account reference (for example, an MCAS workspace or invoice reference). Safaricom says a long-term Paybill requires the applicable business registration document or licence; the required documents depend on the business category.
- **Business Till:** a merchant collection option. Safaricom describes withdrawal routes to the owner's nominated number, an M-PESA agent or a bank account. The nominated number is an authorised withdrawal number; it is not the same thing as wiring a personal customer-payment number directly into MCAS.

Do not apply using another person's identity. The legal merchant/applicant and settlement account must be the right party for the MCAS business. Confirm current eligibility and tariffs directly with Safaricom.

Official information:
- Safaricom Business Paybill: https://www.business.safaricom.co.ke/products/m-pesa-paybill
- Safaricom Business Till: https://www.business.safaricom.co.ke/products/m-pesa-business-till
- Lipa Na M-PESA application portal: https://m-pesaforbusiness.co.ke/apply

## 2. Set up the nominated M-PESA number and bank settlement

During the merchant application, confirm:
- the legal business / proprietor name and registration documents required for your chosen business category;
- the M-PESA mobile number to nominate for merchant administration and withdrawals;
- the business bank account and bank details required for merchant settlement;
- the name and identity of the person authorised to operate the merchant account.

For Paybill, Safaricom's guidance says funds are withdrawn to the bank account supplied during the application. The nominated mobile number accesses merchant functions using the Safaricom business menu / portal. For Business Till, the available withdrawal channels include the nominated number and bank. Follow the instructions Safaricom issues for the product that is approved.

Do not store your M-PESA PIN in MCAS, GitHub, the private .env file, or the browser. The nominated mobile number should stay under your control.

## 3. Create a Daraja developer application (sandbox first)

1. Register at the Safaricom Daraja Developer Portal: https://developer.safaricom.co.ke/. Safaricom supports developer registration as an individual or a company.
2. Create a sandbox application and select the payment API products made available to that account.
3. Read the current Daraja API documentation in the portal and test against the sandbox before requesting production credentials.
4. Complete Safaricom's Go-Live / merchant approval process for the real Paybill or Till and the production app.
5. Configure a stable HTTPS callback URL on the MCAS production domain before live requests are enabled.

The sandbox is for simulated payments only; it cannot transfer money to your M-PESA wallet or bank.

## 4. What MCAS must implement before enabling payments

The payment integration will be server-side only. The planned flow is:

1. An authenticated customer chooses a plan and confirms the amount and M-PESA phone number.
2. MCAS creates a pending payment record with a random internal reference and workspace ownership.
3. MCAS requests an STK Push from Daraja using server-side credentials. Secrets never reach the browser.
4. The customer approves the prompt on the phone.
5. Safaricom sends the result to the configured HTTPS callback. MCAS validates the callback structure and ties it to the pending checkout request.
6. MCAS verifies the transaction status with Safaricom where required, then stores the receipt/reference, amount, currency, shortcode, phone suffix, status and timestamps. Repeated callbacks must be idempotent.
7. Only a verified successful payment changes that workspace's subscription entitlement. A browser redirect, a screenshot, an SMS forwarded by a customer, or a successful STK Push initiation is not proof of payment.
8. An operator can reconcile MCAS payment records against the M-PESA merchant statement and handle reversals, failed/expired prompts, refunds and support cases.

Before production we also need:
- rate limits and replay protection on payment initiation and callbacks;
- server-side status verification as documented by Daraja;
- transaction uniqueness and duplicate-callback handling;
- exact amount, shortcode, phone and reference checks;
- audit logs and restricted access to payment administration;
- daily reconciliation and an operational refund/reversal process;
- production HTTPS, backups and monitoring.

## 5. Credentials required later

When we configure the sandbox, you will enter the following into a private local environment file or a hosting secret manager, depending on the Daraja app:
- consumer key;
- consumer secret;
- approved business shortcode / Till / Paybill details;
- STK Push passkey (where the selected Daraja product requires it);
- exact production callback URL;
- approved transaction type and account-reference format.

**Never paste these credentials, an M-PESA PIN, OTP, or bank details into this chat or commit them to GitHub.** I will provide commands that validate that each value is configured without displaying it.

## Current status

- MCAS subscription billing: disabled.
- Daraja sandbox integration: not yet implemented.
- Production collection and settlement: not configured.
- No payment can be accepted through MCAS at this stage.

This is intentional: payment status must never be guessed or granted from a client-side claim.
