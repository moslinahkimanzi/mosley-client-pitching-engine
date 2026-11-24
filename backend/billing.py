"""Commercial catalogue and deterministic credit accounting rules for MCAS.

Prices are operator-approved KES launch list prices. Keep this catalogue server-side:
the browser may request a SKU but never chooses an amount.
"""
from __future__ import annotations

PLANS = {
    "free": {"name": "Free", "amount_kes": 0, "monthly_credits": 20, "seats": 1},
    "starter": {"name": "Starter", "amount_kes": 2500, "monthly_credits": 150, "seats": 1},
    "growth": {"name": "Growth", "amount_kes": 6500, "monthly_credits": 500, "seats": 1},
    "agency": {"name": "Agency", "amount_kes": 16900, "monthly_credits": 1500, "seats": 1},
}
CREDIT_PACKS = {
    "small": {"name": "Small credit pack", "amount_kes": 1500, "credits": 100},
    "standard": {"name": "Standard credit pack", "amount_kes": 6500, "credits": 500},
    "studio": {"name": "Studio credit pack", "amount_kes": 13000, "credits": 1200},
}
CREDIT_COSTS = {
    "research": 5,
    "business_recheck": 3,
    "audit_1_5_pages": 3,
    "audit_6_10_pages": 5,
    "audit_11_15_pages": 7,
    "competitors_1_3": 6,
    "competitors_4_5": 8,
    "competitors_6_8": 11,
    "ai_generation": 1,
}


def product_for_order(item_type: str, item_code: str):
    if item_type == "subscription":
        return PLANS.get(item_code)
    if item_type == "credits":
        return CREDIT_PACKS.get(item_code)
    return None


def credits_for_audit(max_pages: int) -> int:
    return CREDIT_COSTS["audit_1_5_pages" if max_pages <= 5 else
                        "audit_6_10_pages" if max_pages <= 10 else
                        "audit_11_15_pages"]


def credits_for_competitors(count: int) -> int:
    return CREDIT_COSTS["competitors_1_3" if count <= 3 else
                        "competitors_4_5" if count <= 5 else
                        "competitors_6_8"]
