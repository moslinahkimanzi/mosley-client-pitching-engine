# MCAS payment, M-Pesa and settlement design

## 1. Initial collection approach

The initial application integration is designed around Flutterwave hosted checkout for Kenya because the current Flutterwave Kenya documentation lists both M-Pesa and card payment methods. Checkout is created server-side; secret keys stay in server environment variables.

Current published Kenya pricing lists 2.9% for local wallets/mobile money and 3.2% for local cards; international cards are listed at 4.8%. Flutterwave says these rates exclude VAT and other applicable taxes. Confirm live merchant pricing and settlement terms during onboarding: https://www.flutterwave.com/ke/pricing.

Official payment-method reference: https://developer.flutterwave.com/docs/collections-inflow/payment-methods.

## 1A. Kenyan merchant onboarding if the owner is not yet registered

Flutterwave's currently published Kenya onboarding guidance includes an **Unregistered Businesses** category. It lists items such as a verifiable website URL or social page, proof of residential address, payout details (bank or mobile-money details), estimated monthly sales, a business-activity profile, valid identification and a KRA PIN certificate. The provider decides eligibility and may request additional evidence; this is not a promise of approval. Review the current official checklist before applying:
https://www.flutterwave.com/us/support/onboarding/onboarding-requirements-for-using-flutterwave-in-kenya

This means formal business registration may not be an absolute prerequisite for every unregistered-business application, but a KRA PIN, identity, address and business evidence may still be required. Do not invent or borrow another person's registration or payout details. Use a payout account/wallet in the applicant's own name and ask Flutterwave to confirm the exact acceptable documents for this specific account.

## 2. Monthly subscriptions versus prepaid credits

- Prepaid credits: one-off hosted checkout; add credits only after server-side transaction verification.
- Monthly subscription: a 30-day paid plan; the initial release uses a customer-initiated monthly payment for both M-Pesa and cards.
- M-Pesa monthly renewal is manual: customer starts and approves a new payment each month. Do not describe this as automatic recurring M-Pesa billing.
- Flutterwave Payment Plans are card-only. The provider documentation says adding a payment plan fixes the payment method to card: https://developer.flutterwave.com/docs/recurring-payments/payment-plans. Card auto-renewal should be enabled only after creating the provider plans, completing sandbox cycles, confirming recurring webhook payloads and testing cancellation, retries, account downgrade and idempotent renewals. This initial release does not claim that automatic recurring card renewals are live.

## 3. Payment verification and security

- The app generates the product price, currency and transaction reference server-side. The browser cannot submit an arbitrary amount.
- Checkout redirects are not proof of payment.
- This implementation uses Flutterwave's v3 API. Its webhook guide specifies the `verif-hash` header: compare it in constant time with the secret hash configured in the Flutterwave dashboard and stored as `FLW_SECRET_HASH`. Do not substitute the separate v4/HMAC webhook scheme unless the API integration is migrated to v4. The handler correlates the event to a local order and verifies the transaction by the locally stored reference before fulfilment.
- Before adding credits or activating a plan, the server calls Flutterwave's transaction-verification endpoint and checks successful status, expected reference, exact amount and currency.
- Store unique transaction references and webhook IDs; duplicate events must not grant value more than once.
- Never store card PAN, CVV, OTP, PIN or raw payment credentials in MCAS.
- Keep API secrets server-side. Use HTTPS for the public webhook URL. Configure webhook retries in the provider dashboard.
- A failed verification, amount mismatch, currency mismatch, missing local order or invalid signature must not activate paid features.

Official documentation: https://developer.flutterwave.com/v3.0.0/docs/webhooks and https://developer.flutterwave.com/docs/transaction-verification.

## 4. Settlement to the owner

Flutterwave's settlement documentation says only approved live accounts are eligible for settlement after KYC, and the merchant chooses a bank account or Flutterwave wallet as the settlement destination in the provider dashboard: https://developer.flutterwave.com/docs/payment-operations/settlements.

Therefore:
- Do not collect the user's bank account details in the MCAS customer application.
- Set and later change the owner's settlement bank account inside the approved payment-provider dashboard, subject to KYC.
- Settlement is not the same thing as customers paying by bank transfer.
- Keep settlement reports and reconcile provider gross volume, fees, refunds, chargebacks and net deposits.

Flutterwave's Kenya pricing currently lists KES 100 for bank-account or mobile-money transfers. This is a transfer/payout price and must not be treated as the merchant settlement fee without confirmation from Flutterwave.

## 5. Direct Safaricom M-Pesa option (future)

Safaricom Daraja is its official API platform for integrating M-Pesa into websites and applications: https://developer.safaricom.co.ke/.

Safaricom's Lipa na M-PESA KYC document currently available on its site is titled 2024 Requirements. It says the individual category applies only to Buy Goods; its bank-settlement section asks for an individual KRA PIN certificate and bank evidence, and online businesses must provide a website link and/or approved supporting documentation. The sole-proprietor section asks for a business registration certificate or business permit. This is not a guarantee of approval; Safaricom's latest merchant onboarding decision and KYC requirements control. Confirm current requirements directly with Safaricom before applying:
https://www.safaricom.co.ke/images/Downloads/Lipa-na-M-PESA-Requirements-2024.pdf

If the owner remains an individual, do not assume direct Paybill eligibility. Ask Safaricom whether Buy Goods is the appropriate current product and whether Daraja STK Push is enabled for that merchant account. After formal business registration, revisit whether a sole-proprietor or company merchant product is appropriate.

## 6. Environment setup (do not paste secrets into chat)

The backend supports these server-only settings:

- `MCAS_BILLING_ENABLED`: must remain `false` until sandbox tests pass and the operator has approved the merchant configuration. The checkout API enforces this server-side.
- `FLW_SECRET_KEY`: Flutterwave test key in sandbox and live key only after approval.
- `FLW_SECRET_HASH`: random webhook-signing secret configured identically in Flutterwave dashboard.
- `MCAS_PUBLIC_URL`: public HTTPS base URL used for the checkout return URL in production.

Never commit real values to Git. Keep `.env` outside the repository, restrict file permissions and use a secret manager in production. Do not use production keys on a local or untrusted host.

## 7. Production gate

The existence of a checkout URL does not mean the system is ready to accept live payments. Before enabling production:
1. Verify the merchant account and KYC.
2. Create/configure the webhook URL and secret hash.
3. Test M-Pesa and card flows separately in sandbox.
4. Test invalid signatures, duplicate webhooks, amount/currency mismatches, cancelled and pending transactions, delayed callbacks, timeouts and refunds.
5. Confirm settlement destination and reconciliation statements.
6. Have the business terms, privacy notice, refund/cancellation policy, taxes and bookkeeping reviewed.

The code intentionally defaults to payments disabled until server-side keys and a public URL are configured. It must be tested in sandbox before a production key is added.
