from __future__ import annotations

import asyncio
import json
from datetime import timedelta

from backend.db.pg import tx, utcnow
from backend.services.billing_engine import commit_credits, refund_credits
from backend.services.evidence_pipeline import collect_deterministic_site_evidence
from backend.workers.celery_app import celery_app


def _run_async(coro):
    return asyncio.run(coro)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5)
def run_site_audit_task(self, job_id: str, user_id: str, target_url: str) -> dict:
    async def _execute():
        async with tx() as c:
            await c.execute(
                "UPDATE website_audit_reports SET status='PROCESSING' WHERE id=? AND user_id=?",
                (job_id, user_id),
            )
        try:
            evidence = await collect_deterministic_site_evidence(target_url)
            async with tx() as c:
                await c.execute(
                    """UPDATE website_audit_reports
                          SET status='COMPLETED', result_json=?
                        WHERE id=? AND user_id=?""",
                    (json.dumps(evidence), job_id, user_id),
                )
                await commit_credits(c, job_id)
            return {"job_id": job_id, "status": "COMPLETED"}
        except Exception as exc:
            async with tx() as c:
                await c.execute(
                    """UPDATE website_audit_reports
                          SET status='FAILED', error_message=?
                        WHERE id=? AND user_id=?""",
                    (str(exc)[:300], job_id, user_id),
                )
                await refund_credits(c, job_id, f"Task failure: {type(exc).__name__}")
            raise

    return _run_async(_execute())


@celery_app.task
def reap_stuck_reservations() -> int:
    """Auto-refunds any RESERVED credit entries stuck longer than 15 minutes."""
    async def _reap() -> int:
        cutoff = utcnow() - timedelta(minutes=15)
        refunded_count = 0
        async with tx() as c:
            stuck = await c.all(
                """SELECT job_id FROM billing_credit_ledger
                    WHERE status='RESERVED' AND created_at < ?""",
                (cutoff,),
            )
            for row in stuck:
                if await refund_credits(c, str(row["job_id"]), "Auto-refund: job timed out (>15m)"):
                    refunded_count += 1
        return refunded_count

    return _run_async(_reap())
