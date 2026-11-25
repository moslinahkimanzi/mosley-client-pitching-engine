from __future__ import annotations

import asyncio
import time
from typing import Any, Literal

import httpx
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from backend.core.security import validate_safe_external_url
from backend.db.pg import utcnow

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class VerifiedFinding(BaseModel):
    finding: str
    source: str
    evidence_id: str
    timestamp: str
    confidence_score: int = Field(ge=0, le=100)
    verification_status: Literal[
        "CONFIRMED_FINDING",
        "STRONG_EVIDENCE",
        "POSSIBLE_OPPORTUNITY",
        "UNABLE_TO_VERIFY",
        "OUTDATED_EVIDENCE",
    ]
    limitations: str


async def collect_deterministic_site_evidence(raw_url: str) -> dict[str, Any]:
    """Performs SSRF-safe, two-pass HTTP verification so bot blocks are never misreported as downtime."""
    safe_url = validate_safe_external_url(raw_url)
    checked_at = utcnow().isoformat()
    evidence_items: dict[str, dict[str, Any]] = {}

    async def _single_probe() -> dict[str, Any]:
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=True, max_redirects=5, headers=BROWSER_HEADERS
            ) as client:
                resp = await client.get(safe_url)
                elapsed_ms = round((time.perf_counter() - t0) * 1000)
                return {
                    "ok": True,
                    "status_code": resp.status_code,
                    "final_url": str(resp.url),
                    "elapsed_ms": elapsed_ms,
                    "html": resp.text[:150_000] if "text/html" in resp.headers.get("content-type", "") else "",
                }
        except httpx.TimeoutException:
            return {"ok": False, "error": "TIMEOUT", "elapsed_ms": round((time.perf_counter() - t0) * 1000)}
        except httpx.RequestError as exc:
            return {"ok": False, "error": f"NETWORK_ERROR:{type(exc).__name__}"}

    probe_1 = await _single_probe()
    probe_2 = None
    if not probe_1.get("ok") or int(probe_1.get("status_code", 200)) >= 400:
        await asyncio.sleep(5)
        probe_2 = await _single_probe()

    active_probe = probe_2 if (probe_2 and probe_2.get("ok")) else probe_1
    status_code = active_probe.get("status_code")

    if status_code in (403, 429):
        availability = "BOT_PROTECTION_DETECTED"
        note = f"Site returned HTTP {status_code} (WAF/bot protection); not confirmed down."
    elif not active_probe.get("ok") or (status_code and status_code >= 500):
        availability = "UNREACHABLE_OR_SERVER_ERROR"
        note = f"Two consecutive probes failed ({active_probe.get('error') or status_code}) on {checked_at}."
    else:
        availability = "ONLINE"
        note = f"HTTP {status_code} in {active_probe.get('elapsed_ms')}ms."

    evidence_items["EV-01"] = {
        "metric": "availability",
        "value": availability,
        "status_code": status_code,
        "elapsed_ms": active_probe.get("elapsed_ms"),
        "source": active_probe.get("final_url", safe_url),
        "timestamp": checked_at,
        "note": note,
    }

    html = active_probe.get("html", "")
    if html:
        soup = BeautifulSoup(html, "html.parser")
        title = (soup.title.string or "").strip() if soup.title else ""
        meta_desc_tag = soup.find("meta", attrs={"name": "description"})
        meta_desc = (meta_desc_tag.get("content") or "").strip() if meta_desc_tag else ""
        viewport = soup.find("meta", attrs={"name": "viewport"}) is not None
        h1_count = len(soup.find_all("h1"))

        evidence_items["EV-02"] = {
            "metric": "seo_and_mobile_basics",
            "title_present": bool(title),
            "title_length": len(title),
            "meta_description_present": bool(meta_desc),
            "viewport_mobile_tag": viewport,
            "h1_count": h1_count,
            "source": active_probe.get("final_url", safe_url),
            "timestamp": checked_at,
        }

    return {
        "target_url": safe_url,
        "checked_at": checked_at,
        "evidence": evidence_items,
        "sanitized_text_excerpt": BeautifulSoup(html, "html.parser").get_text(" ", strip=True)[:6000] if html else "",
    }


def filter_verified_findings(
    raw_findings: list[dict[str, Any]], valid_evidence_ids: set[str]
) -> list[VerifiedFinding]:
    """Strips any LLM claim that fails Pydantic validation or cites a nonexistent evidence_id."""
    verified: list[VerifiedFinding] = []
    for item in raw_findings:
        if item.get("evidence_id") not in valid_evidence_ids:
            continue
        try:
            verified.append(VerifiedFinding.model_validate(item))
        except Exception:
            continue
    return verified
