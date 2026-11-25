from __future__ import annotations

import hmac
import os
import secrets
from typing import Any

from fastapi import HTTPException

from backend.core.security import is_unlimited_admin
from backend.db.pg import Tx, utcnow


async def user_has_unlimited_access_pg(c: Tx, user_id: str) -> bool:
    """Allows unlimited access for verified admin emails (Google-linked or email-verified)."""
    row = await c.one(
        "SELECT id, email, google_subject, is_admin, is_verified FROM users WHERE id=?",
        (user_id,),
    )
    if not row:
        return False
    if not (row.get("google_subject") or row.get("is_verified")):
        return False
    return bool(row.get("is_admin") or is_unlimited_admin(row))


async def reserve_credits_pg(
    c: Tx,
    user_id: str,
    amount: int,
    reason: str,
    job_id: str,
) -> dict[str, Any]:
    """Atomically reserves credits with PostgreSQL FOR UPDATE row locking using MCAS's exact ledger schema."""
    if amount <= 0:
        return {"status": "NOOP", "charged": 0}

    ref_reserved = f"reserve:{job_id}"
    existing = await c.one(
        "SELECT id, delta_monthly, delta_purchased FROM billing_credit_ledger WHERE reference=?",
        (ref_reserved,),
    )
    if existing is not None:
        return {"status": "ALREADY_RESERVED", "ledger_id": existing["id"]}

    now = utcnow()
    ledger_id = secrets.token_urlsafe(16)

    if await user_has_unlimited_access_pg(c, user_id):
        await c.execute(
            """INSERT INTO billing_credit_ledger
               (id, user_id, delta_monthly, delta_purchased, reason, reference, created_at)
               VALUES (?, ?, 0, 0, ?, ?, ?)""",
            (ledger_id, user_id, f"admin_unlimited:{reason[:75]}", f"admin:{job_id}", now),
        )
        return {"status": "ADMIN_BYPASS", "ledger_id": ledger_id, "charged": 0}

    acct = await c.one(
        """SELECT user_id, monthly_credits, purchased_credits
             FROM billing_accounts
            WHERE user_id=?
            FOR UPDATE""",
        (user_id,),
    )
    if acct is None:
        raise HTTPException(402, "Billing account not found.")

    monthly = int(acct["monthly_credits"])
    purchased = int(acct["purchased_credits"])
    if monthly + purchased < amount:
        raise HTTPException(402, "Not enough MCAS credits. Choose a monthly plan or buy a credit pack.")

    used_monthly = min(monthly, amount)
    used_purchased = amount - used_monthly

    await c.execute(
        """UPDATE billing_accounts
              SET monthly_credits=?, purchased_credits=?, updated_at=?
            WHERE user_id=?""",
        (monthly - used_monthly, purchased - used_purchased, now, user_id),
    )
    await c.execute(
        """INSERT INTO billing_credit_ledger
           (id, user_id, delta_monthly, delta_purchased, reason, reference, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (ledger_id, user_id, -used_monthly, -used_purchased, f"reserve:{reason[:85]}", ref_reserved, now),
    )
    return {
        "status": "RESERVED",
        "ledger_id": ledger_id,
        "used_monthly": used_monthly,
        "used_purchased": used_purchased,
    }


async def commit_credits_pg(c: Tx, job_id: str) -> None:
    await c.execute(
        "UPDATE billing_credit_ledger SET reference=? WHERE reference=?",
        (f"committed:{job_id}", f"reserve:{job_id}"),
    )


async def refund_credits_pg(c: Tx, job_id: str, failure_reason: str) -> bool:
    """Restores exact monthly and purchased credits if a reserved job fails or times out."""
    ref_reserved = f"reserve:{job_id}"
    entry = await c.one(
        """SELECT id, user_id, delta_monthly, delta_purchased, reason
             FROM billing_credit_ledger
            WHERE reference=?
            FOR UPDATE""",
        (ref_reserved,),
    )
    if entry is None:
        return False

    refund_monthly = abs(int(entry["delta_monthly"]))
    refund_purchased = abs(int(entry["delta_purchased"]))
    now = utcnow()
    user_id = str(entry["user_id"])

    await c.execute(
        """UPDATE billing_accounts
              SET monthly_credits = monthly_credits + ?,
                  purchased_credits = purchased_credits + ?,
                  updated_at = ?
            WHERE user_id=?""",
        (refund_monthly, refund_purchased, now, user_id),
    )
    await c.execute(
        "UPDATE billing_credit_ledger SET reference=? WHERE id=?",
        (f"refunded:{job_id}", str(entry["id"])),
    )
    await c.execute(
        """INSERT INTO billing_credit_ledger
           (id, user_id, delta_monthly, delta_purchased, reason, reference, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            secrets.token_urlsafe(16),
            user_id,
            refund_monthly,
            refund_purchased,
            f"refund:{failure_reason[:85]}",
            f"refund_credit:{job_id}",
            now,
        ),
    )
    return True


def verify_flutterwave_signature(header_hash: str | None) -> bool:
    secret = os.environ.get("FLUTTERWAVE_SECRET_HASH", "")
    if not secret or not header_hash:
        return False
    return hmac.compare_digest(secret.strip(), header_hash.strip())
