"""MCAS USD pricing and Flutterwave payment helpers.

Prices and entitlements are denominated in USD. Flutterwave's Kenyan M-Pesa
rail only accepts KES, so M-Pesa checkout uses a fresh, operator-configured
USD/KES quote. USD card checkout is separate and never silently converts.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

PLANS = {
    "starter": {"name": "Starter", "amount_usd_cents": 1200, "credits": 100, "period_days": 30,
                "features": ["Local business research", "Website intelligence", "Email and proposal drafts"]},
    "growth": {"name": "Growth", "amount_usd_cents": 2900, "credits": 350, "period_days": 30,
               "features": ["Everything in Starter", "Higher research volume", "Priority support"]},
    "agency": {"name": "Agency", "amount_usd_cents": 7900, "credits": 1000, "period_days": 30,
               "features": ["Everything in Growth", "Multi-client workflows", "Highest included usage"]},
}
CREDIT_PACKS = {
    "mini": {"name": "Mini credit pack", "amount_usd_cents": 500, "credits": 30},
    "standard": {"name": "Standard credit pack", "amount_usd_cents": 1500, "credits": 110},
    "pro": {"name": "Pro credit pack", "amount_usd_cents": 4900, "credits": 400},
}
CREDIT_COSTS = {
    "research_run": 5,
    "website_audit": 2,
    "ai_draft": 2,
    "proposal_generation": 3,
    "export_report": 1,
}


def amount_usd(cents: int) -> str:
    return f"{Decimal(int(cents)) / Decimal(100):.2f}"


def get_usd_kes_rate() -> Decimal | None:
    """Return an operator-configured FX quote only when its date is recent."""
    raw_rate = os.getenv("MCAS_USD_KES_RATE", "").strip()
    raw_date = os.getenv("MCAS_USD_KES_RATE_DATE", "").strip()
    if not raw_rate or not raw_date:
        return None
    try:
        rate = Decimal(raw_rate)
        rate_date = date.fromisoformat(raw_date)
        age_days = (datetime.now(timezone.utc).date() - rate_date).days
        if not rate.is_finite() or rate <= 0 or rate > Decimal("10000"):
            return None
        if age_days < 0 or age_days > 3:
            return None
        return rate
    except Exception:
        return None


def mpesa_kes_amount(usd_cents: int, rate: Decimal) -> int:
    usd = Decimal(int(usd_cents)) / Decimal(100)
    return int((usd * rate).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def payment_quote(usd_cents: int, payment_method: str, rate: Decimal | None = None) -> dict[str, Any]:
    """Build a server-authoritative provider amount for USD card or KES M-Pesa."""
    usd_value = amount_usd(usd_cents)
    if payment_method == "card":
        return {"base_amount_usd_cents": int(usd_cents), "base_amount_usd": usd_value,
                "provider_amount": usd_value, "provider_currency": "USD",
                "payment_method": "card", "exchange_rate": None, "amount_kes": 0}
    if payment_method == "mpesa":
        if rate is None:
            raise ValueError("M-Pesa checkout requires a current MCAS_USD_KES_RATE and MCAS_USD_KES_RATE_DATE.")
        kes = mpesa_kes_amount(usd_cents, rate)
        return {"base_amount_usd_cents": int(usd_cents), "base_amount_usd": usd_value,
                "provider_amount": str(kes), "provider_currency": "KES",
                "payment_method": "mpesa", "exchange_rate": str(rate), "amount_kes": kes}
    raise ValueError("Unsupported payment method.")


def public_catalog() -> dict[str, Any]:
    def present(items):
        return {code: {**item, "amount_usd": amount_usd(item["amount_usd_cents"])}
                for code, item in items.items()}
    return {
        "currency": "USD",
        "plans": present(PLANS),
        "credit_packs": present(CREDIT_PACKS),
        "credit_costs": CREDIT_COSTS,
        "payment_methods": {
            "card": {"currency": "USD", "available": flutterwave_ready(),
                     "label": "Pay by card (USD)"},
            "mpesa": {"currency": "KES", "available": flutterwave_ready() and get_usd_kes_rate() is not None,
                      "label": "Pay by M-Pesa (KES conversion)"},
        },
        "mpesa_quote": ({"usd_kes_rate": str(get_usd_kes_rate()),
                         "rate_date": os.getenv("MCAS_USD_KES_RATE_DATE", "")}
                        if get_usd_kes_rate() is not None else None),
        "billing_notes": [
            "All plans and credit packs are priced and accounted for in USD.",
            "USD card transactions are charged in USD.",
            "Kenyan M-Pesa only accepts KES; M-Pesa checkout converts the USD list price using the displayed, dated operator-configured rate.",
            "A subscription is a 30-day entitlement renewed only after a verified payment.",
            "Automatic M-Pesa recurring debits are not enabled.",
            "Credit balances are ledger-backed; credits are not cash and are non-transferable.",
        ],
    }


def flutterwave_ready() -> bool:
    return bool(os.getenv("FLW_SECRET_KEY", "").strip()
                and os.getenv("FLW_SECRET_HASH", "").strip()
                and os.getenv("MCAS_PUBLIC_URL", "").strip().startswith("https://"))


def initialize_flutterwave_checkout(*, tx_ref: str, amount: str, currency: str,
                                    payment_method: str, email: str, customer_id: str,
                                    item_type: str, item_code: str) -> dict[str, Any]:
    key = os.getenv("FLW_SECRET_KEY", "").strip()
    public_url = os.getenv("MCAS_PUBLIC_URL", "").strip().rstrip("/")
    if not key or not public_url.startswith("https://"):
        raise RuntimeError("Flutterwave is not configured for secure production checkout.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{12,100}", tx_ref):
        raise ValueError("Invalid transaction reference.")
    if payment_method == "card" and currency != "USD":
        raise ValueError("Card checkout must use USD.")
    if payment_method == "mpesa" and currency != "KES":
        raise ValueError("Kenyan M-Pesa checkout must use KES.")
    if payment_method not in {"card", "mpesa"}:
        raise ValueError("Unsupported payment method.")
    payload = {
        "tx_ref": tx_ref, "amount": str(amount), "currency": currency,
        "redirect_url": public_url + "/?billing=return",
        "payment_options": "card" if payment_method == "card" else "mpesa",
        "customer": {"email": email, "name": email.split("@")[0]},
        "customizations": {"title": "MCAS", "description": "MCAS " + item_type.replace("_", " ")},
        "meta": {"customer_id": customer_id, "item_type": item_type, "item_code": item_code,
                 "base_currency": "USD", "payment_method": payment_method},
    }
    request = urllib.request.Request(
        "https://api.flutterwave.com/v3/payments",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                 "Accept": "application/json", "User-Agent": "MCAS/1.4"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read(200000))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        raise RuntimeError("Payment provider checkout could not be initialized.") from exc
    if data.get("status") != "success" or not isinstance(data.get("data"), dict):
        raise RuntimeError("Payment provider did not return a checkout session.")
    link = data["data"].get("link")
    if not isinstance(link, str) or not link.startswith("https://checkout.flutterwave.com/"):
        raise RuntimeError("Payment provider returned an invalid checkout URL.")
    return {"checkout_url": link}


def verify_flutterwave_transaction(transaction_id: str) -> dict[str, Any]:
    key = os.getenv("FLW_SECRET_KEY", "").strip()
    if not key or not str(transaction_id).isdigit():
        raise RuntimeError("Payment verification is not configured or transaction ID is invalid.")
    request = urllib.request.Request(
        "https://api.flutterwave.com/v3/transactions/" + str(transaction_id) + "/verify",
        headers={"Authorization": "Bearer " + key, "Accept": "application/json",
                 "User-Agent": "MCAS/1.4"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read(200000))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        raise RuntimeError("Payment provider verification request failed.") from exc
    if data.get("status") != "success" or not isinstance(data.get("data"), dict):
        raise RuntimeError("Payment provider could not verify the transaction.")
    return data["data"]
