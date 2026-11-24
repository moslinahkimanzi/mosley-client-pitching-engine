"""MCAS billing catalogue and payment-provider helpers.

Flutterwave checkout is deliberately server initiated. A successful browser redirect
never grants entitlements; only a server-side transaction verification may do so.
"""
from __future__ import annotations

import os
import re
import urllib.error
import urllib.parse
import urllib.request
import json
from typing import Any

PLANS = {
    "starter": {"name": "Starter", "amount_kes": 1499, "credits": 100, "period_days": 30,
                "features": ["Local business research", "Website intelligence", "Email and proposal drafts"]},
    "growth": {"name": "Growth", "amount_kes": 3999, "credits": 350, "period_days": 30,
               "features": ["Everything in Starter", "Higher research volume", "Priority support"]},
    "agency": {"name": "Agency", "amount_kes": 9999, "credits": 1000, "period_days": 30,
               "features": ["Everything in Growth", "Multi-client workflows", "Highest included usage"]},
}
CREDIT_PACKS = {
    "mini": {"name": "Mini credit pack", "amount_kes": 499, "credits": 30},
    "standard": {"name": "Standard credit pack", "amount_kes": 1499, "credits": 110},
    "pro": {"name": "Pro credit pack", "amount_kes": 4999, "credits": 400},
}
CREDIT_COSTS = {
    "research_run": 5,
    "website_audit": 2,
    "ai_draft": 2,
    "proposal_generation": 3,
    "export_report": 1,
}


def public_catalog() -> dict[str, Any]:
    return {"currency": "KES", "plans": PLANS, "credit_packs": CREDIT_PACKS,
            "credit_costs": CREDIT_COSTS,
            "billing_notes": [
                "Prices are proposed launch prices and should be validated against provider fees, taxes and operating costs.",
                "A subscription is a 30-day entitlement renewed only after a verified payment.",
                "M-Pesa automatic recurring debits are not enabled by this integration.",
                "Credit balances are ledger-backed; credits are not cash and are non-transferable."
            ]}


def flutterwave_ready() -> bool:
    return bool(os.getenv("FLW_SECRET_KEY", "").strip()
                and os.getenv("FLW_SECRET_HASH", "").strip()
                and os.getenv("MCAS_PUBLIC_URL", "").strip().startswith("https://"))


def initialize_flutterwave_checkout(*, tx_ref: str, amount_kes: int, email: str,
                                    customer_id: str, item_type: str, item_code: str) -> dict[str, Any]:
    key = os.getenv("FLW_SECRET_KEY", "").strip()
    public_url = os.getenv("MCAS_PUBLIC_URL", "").strip().rstrip("/")
    if not key or not public_url.startswith("https://"):
        raise RuntimeError("Flutterwave is not configured for secure production checkout.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{12,100}", tx_ref):
        raise ValueError("Invalid transaction reference.")
    payload = {
        "tx_ref": tx_ref, "amount": str(amount_kes), "currency": "KES",
        "redirect_url": public_url + "/?billing=return",
        "payment_options": "card,mobilemoneykenya",
        "customer": {"email": email, "name": email.split("@")[0]},
        "customizations": {"title": "MCAS", "description": "MCAS " + item_type.replace("_", " ")},
        "meta": {"customer_id": customer_id, "item_type": item_type, "item_code": item_code},
    }
    request = urllib.request.Request(
        "https://api.flutterwave.com/v3/payments",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                 "Accept": "application/json", "User-Agent": "MCAS/1.3"},
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
                 "User-Agent": "MCAS/1.3"},
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
