"""Evidence-led website assessment primitives for MCAS.

Scores are transparent heuristics, not certifications or predictions of revenue.
Unknown signals are excluded from denominators rather than treated as failures.
"""
from __future__ import annotations

from typing import Any


def _score(signals: list[tuple[str, bool | None, int, str, str]]) -> dict[str, Any]:
    applicable = [(name, passed, weight, evidence, recommendation)
                  for name, passed, weight, evidence, recommendation in signals
                  if passed is not None]
    total = sum(weight for _, _, weight, _, _ in applicable)
    earned = sum(weight for _, passed, weight, _, _ in applicable if passed)
    findings = []
    for name, passed, weight, evidence, recommendation in signals:
        if passed is None:
            findings.append({"signal": name, "status": "unknown", "weight": weight,
                             "evidence": evidence or "Not assessed",
                             "recommendation": "Collect reliable evidence before scoring this signal."})
        else:
            findings.append({"signal": name, "status": "pass" if passed else "issue",
                             "weight": weight, "evidence": evidence,
                             "recommendation": "" if passed else recommendation})
    return {
        "score": round(100 * earned / total) if total else None,
        "assessed_signals": len(applicable),
        "total_signals": len(signals),
        "coverage_percent": round(100 * len(applicable) / len(signals)) if signals else 0,
        "findings": findings,
    }


def assess_website(website_audit: dict | None, website_state: str | None = None,
                   business: dict | None = None) -> dict[str, Any]:
    """Calculate Technical Health, Business Readiness and Commercial Opportunity."""
    audit = website_audit or {}
    business = business or {}
    status = audit.get("http_status")
    html = str(audit.get("content_type") or "").lower()
    is_html = ("html" in html) if html else None
    reachable = (200 <= int(status) < 400) if isinstance(status, int) else None

    technical = _score([
        ("Public page responds successfully", reachable, 25,
         f"HTTP {status}" if status is not None else "No live HTTP response recorded",
         "Investigate availability, DNS, TLS and server response before describing the site as broken."),
        ("HTML page available for inspection", is_html, 10,
         str(audit.get("content_type") or "Content type not recorded"),
         "Confirm the intended page and response type; non-HTML pages may be intentional."),
        ("Page title present", (bool(audit.get("title")) if is_html else None), 15,
         f"Title: {audit.get('title')}" if audit.get("title") else ("No title detected" if is_html else "Not assessed"),
         "Add a concise, accurate title describing the page."),
        ("Meta description present", audit.get("has_meta_description") if is_html else None, 10,
         "Meta description detected" if audit.get("has_meta_description") is True else ("No meta description detected" if audit.get("has_meta_description") is False else "Not assessed"),
         "Add a unique, accurate meta description to important pages."),
        ("Mobile viewport metadata present", audit.get("has_viewport_meta") if is_html else None, 15,
         "Viewport metadata detected" if audit.get("has_viewport_meta") is True else ("No viewport metadata detected" if audit.get("has_viewport_meta") is False else "Not assessed"),
         "Add a responsive viewport declaration and verify layout on real devices."),
        ("Primary heading detected", audit.get("has_h1") if is_html else None, 10,
         "H1 detected" if audit.get("has_h1") is True else ("No H1 detected" if audit.get("has_h1") is False else "Not assessed"),
         "Review semantic heading structure and add a clear primary heading where appropriate."),
        ("TLS / certificate validity", None, 15, "Not measured by the current lightweight page fetch",
         "Use a dedicated TLS and certificate test before making security claims."),
    ])

    readiness = _score([
        ("Public phone number available", bool(business.get("phone")) if "phone" in business else None, 20,
         "Phone recorded" if business.get("phone") else ("No phone recorded" if "phone" in business else "Not assessed"),
         "Confirm the preferred customer contact channel with the business owner."),
        ("Public contact email available", bool(business.get("email")) if "email" in business else None, 15,
         "Email recorded" if business.get("email") else ("No email recorded" if "email" in business else "Not assessed"),
         "Confirm a monitored business email address."),
        ("Service information reviewed", business.get("services_clear"), 20,
         "Service information manually reviewed" if business.get("services_clear") is True else "Not assessed from a single-page technical fetch",
         "Review service descriptions, coverage and current information with the owner."),
        ("Conversion path reviewed", business.get("conversion_path_clear"), 20,
         "Conversion path manually reviewed" if business.get("conversion_path_clear") is True else "Not assessed from a single-page technical fetch",
         "Check that visitors can complete a clear call, booking, enquiry or purchase journey."),
        ("Mobile usability tested on device", business.get("mobile_tested"), 15,
         "Real-device mobile test recorded" if business.get("mobile_tested") is True else "Not tested on a real mobile device",
         "Test navigation, text, forms and calls to action on real mobile devices."),
        ("Opening hours / location reviewed", business.get("location_hours_verified"), 10,
         "Business location and hours manually verified" if business.get("location_hours_verified") is True else "Not assessed",
         "Confirm current location and opening hours with an authoritative business source."),
    ])

    # Opportunity is a priority index, not buying intent. Missing website links are weak signals only.
    state = website_state or "unknown"
    opportunity_signals = [
        ("Confirmed website availability defect", state == "broken" if state != "unknown" else None, 35,
         "Live check returned a qualifying HTTP error" if state == "broken" else ("No confirmed availability defect" if state != "unknown" else "Website status unknown"),
         "Recheck from another network and confirm with the owner before offering repair."),
        ("Confirmed technical improvement finding", state == "needs_improvement" if state != "unknown" else None, 25,
         "Limited page scan detected missing metadata basics" if state == "needs_improvement" else "No such finding recorded",
         "Validate the finding across important pages and assess its actual impact."),
        ("Website link absent from discovery listing", state == "not_listed" if state != "unknown" else None, 10,
         "Discovery provider returned no website URL; this does not prove no website exists" if state == "not_listed" else "No missing-link signal recorded",
         "Search for the official site and ask the business before suggesting a new website."),
        ("Contact route available for legitimate enquiry", bool(business.get("phone") or business.get("email")) if ("phone" in business or "email" in business) else None, 10,
         "At least one public contact detail recorded" if (business.get("phone") or business.get("email")) else "No contact detail recorded",
         "Confirm the contact details and applicable outreach permissions."),
        ("Owner-confirmed improvement need", business.get("owner_confirmed_need"), 20,
         "Business owner confirmed the need" if business.get("owner_confirmed_need") is True else "Not confirmed with the business owner",
         "Ask whether the owner wants help; do not infer purchase intent from a scan."),
    ]
    opportunity = _score(opportunity_signals)
    opportunity["interpretation"] = "Priority for human review only; not a probability of purchase, revenue forecast or claim that the business needs a website."
    opportunity["website_state"] = state

    return {
        "technical_health": technical,
        "business_readiness": readiness,
        "commercial_opportunity": opportunity,
        "methodology": {
            "version": "1.0",
            "generated_from": "Recorded public-page observations and explicitly supplied business facts",
            "limitations": [
                "The current fetch checks one public page and a small set of HTML signals only.",
                "Accessibility, real mobile usability, performance, full SEO, security posture and conversion flows are not certified.",
                "Unknown signals are excluded from score denominators and shown separately.",
                "A missing website link in a search listing does not prove that a business has no website.",
                "Commercial Opportunity is a human-review priority index, not buying intent or expected revenue."
            ]
        }
    }
