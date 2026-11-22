"""Bounded, safe and evidence-oriented public website audit engine.

This module deliberately avoids JavaScript execution, form submission, authentication
bypass, intrusive vulnerability tests and third-party crawling.
"""
from __future__ import annotations

import re
import time
from collections import Counter
from urllib.parse import urljoin, urlparse, urldefrag


def advanced_site_audit(initial_url: str, fetcher, max_pages: int = 10) -> dict:
    """Crawl a small number of same-host public HTML pages using a caller-supplied SSRF-safe fetcher."""
    try:
        max_pages = max(1, min(int(max_pages), 15))
    except (TypeError, ValueError):
        max_pages = 10

    started = time.perf_counter()
    root = fetcher(initial_url)
    root_url = root.get("url") or initial_url
    root_host = (urlparse(root_url).hostname or "").lower()
    if not root_host:
        raise ValueError("A public website URL is required.")

    queue = [root_url]
    seen = set()
    pages = []
    findings = []
    finding_keys = set()

    def add_finding(severity, code, title, description, recommendation, url=None, evidence=None):
        key = (code, url or "")
        if key in finding_keys:
            return
        finding_keys.add(key)
        findings.append({
            "severity": severity,
            "code": code,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "url": url,
            "evidence": evidence,
        })

    while queue and len(pages) < max_pages:
        requested = queue.pop(0)
        requested, _fragment = urldefrag(requested)
        parsed_request = urlparse(requested)
        if parsed_request.scheme not in {"http", "https"} or (parsed_request.hostname or "").lower() != root_host:
            continue
        if requested in seen:
            continue
        seen.add(requested)

        if requested == root_url:
            page = root
        else:
            try:
                page = fetcher(requested)
            except Exception as exc:
                pages.append({
                    "url": requested,
                    "http_status": None,
                    "title": None,
                    "response_time_ms": None,
                    "error": str(getattr(exc, "detail", "The page could not be checked safely"))[:180],
                })
                add_finding("medium", "page_fetch_failed", "An internal page could not be checked",
                            "A same-host link could not be fetched by the bounded public-page checker.",
                            "Open the link manually and confirm whether it is intentionally restricted, moved or unavailable.",
                            requested)
                continue

        final_url = page.get("url") or requested
        final_host = (urlparse(final_url).hostname or "").lower()
        if final_host != root_host:
            pages.append({
                "url": requested, "http_status": page.get("http_status"), "title": page.get("title"),
                "response_time_ms": page.get("response_time_ms"), "redirected_off_host": True,
            })
            add_finding("info", "external_redirect_not_crawled", "A page redirected to another host",
                        "MCAS stopped crawling after the redirect left the starting hostname.",
                        "Review the redirect destination manually; external hosts are not included in this crawl.",
                        requested, final_url)
            continue

        status = page.get("http_status")
        title = page.get("title")
        html_page = str(page.get("content_type") or "").lower()
        is_html = "html" in html_page or page.get("has_viewport_meta") is not None
        item = {
            "url": final_url,
            "http_status": status,
            "content_type": page.get("content_type"),
            "title": title,
            "response_time_ms": page.get("response_time_ms"),
            "https": urlparse(final_url).scheme == "https",
            "has_viewport_meta": page.get("has_viewport_meta"),
            "has_meta_description": page.get("has_meta_description"),
            "has_h1": page.get("has_h1"),
            "has_lang": page.get("has_lang"),
            "images_total": page.get("images_total"),
            "images_missing_alt": page.get("images_missing_alt"),
            "forms_total": page.get("forms_total"),
            "form_controls_total": page.get("form_controls_total"),
            "form_controls_without_label": page.get("form_controls_without_label"),
            "mixed_content_references": page.get("mixed_content_references"),
            "security_headers": page.get("security_headers") or {},
            "canonical_url": page.get("canonical_url"),
            "error": page.get("note") if not is_html else None,
        }
        pages.append(item)

        if status is not None and int(status) >= 400:
            severity = "high" if int(status) >= 500 else "medium"
            add_finding(severity, "http_error", "A page returned HTTP " + str(status),
                        "The checked public URL returned an HTTP error response.",
                        "Confirm the route, hosting configuration and intended access policy; then repeat the check.",
                        final_url, "HTTP " + str(status))
            continue
        if not is_html:
            add_finding("info", "non_html_page", "A checked URL was not an HTML page",
                        "The response was not HTML, so page structure and metadata could not be analysed.",
                        "Review non-HTML resources separately if they are important to the customer journey.",
                        final_url, str(page.get("content_type") or "Content type not supplied"))
            continue

        if not item["https"]:
            add_finding("high", "https_not_used", "The page is not served over HTTPS",
                        "The checked page URL uses plain HTTP.",
                        "Configure HTTPS with a valid certificate and redirect HTTP requests to HTTPS.",
                        final_url, "URL scheme: http")
        if page.get("has_viewport_meta") is False:
            add_finding("medium", "missing_viewport", "Mobile viewport metadata was not detected",
                        "The checked HTML page did not expose a viewport meta tag.",
                        "Add a responsive viewport declaration and test the actual layout on mobile devices.",
                        final_url)
        if not title:
            add_finding("medium", "missing_title", "The page title was not detected",
                        "The checked HTML page did not expose a non-empty title element.",
                        "Add a unique, descriptive title that accurately reflects the page content.",
                        final_url)
        if page.get("has_meta_description") is False:
            add_finding("low", "missing_meta_description", "Meta description was not detected",
                        "The checked HTML page did not expose a meta description.",
                        "Add a concise, page-specific description that accurately summarises the content.",
                        final_url)
        if page.get("has_h1") is False:
            add_finding("low", "missing_h1", "A main H1 heading was not detected",
                        "The checked HTML page did not expose an H1 element.",
                        "Use a clear primary heading and a meaningful heading hierarchy where appropriate.",
                        final_url)
        if page.get("has_lang") is False:
            add_finding("low", "missing_html_lang", "HTML document language was not declared",
                        "The root HTML element did not expose a lang attribute.",
                        "Set the document language, for example lang=\"en\", to support assistive technology.",
                        final_url)
        missing_alt = int(page.get("images_missing_alt") or 0)
        if missing_alt:
            add_finding("medium", "images_missing_alt", "Images without alt attributes were detected",
                        str(missing_alt) + " of " + str(page.get("images_total") or 0) + " inspected image element(s) lacked an alt attribute.",
                        "Add meaningful alternative text to informative images and empty alt text to decorative images.",
                        final_url, str(missing_alt) + " image(s)")
        unlabelled = int(page.get("form_controls_without_label") or 0)
        if unlabelled:
            add_finding("medium", "form_controls_without_label", "Some form controls may lack accessible labels",
                        str(unlabelled) + " form control(s) did not expose a directly detectable label, aria-label or aria-labelledby attribute.",
                        "Give every interactive field a programmatic label and test keyboard and screen-reader use.",
                        final_url, str(unlabelled) + " form control(s)")
        mixed = int(page.get("mixed_content_references") or 0)
        if mixed and item["https"]:
            add_finding("high", "mixed_content", "HTTP resources were referenced by an HTTPS page",
                        str(mixed) + " resource reference(s) use http:// on a page loaded over HTTPS.",
                        "Serve all page resources over HTTPS and remove insecure resource references.",
                        final_url, str(mixed) + " mixed-content reference(s)")
        if float(page.get("response_time_ms") or 0) > 3000:
            add_finding("low", "slow_response", "The page response was slower than three seconds",
                        "The server response time observed by this single request exceeded three seconds; network conditions can affect this measurement.",
                        "Repeat the measurement from representative locations and review caching, hosting, image size and server response time.",
                        final_url, str(page.get("response_time_ms")) + " ms")
        headers = page.get("security_headers") or {}
        if item["https"] and not headers.get("strict_transport_security"):
            add_finding("low", "missing_hsts", "Strict-Transport-Security header was not detected",
                        "The response did not include an HSTS response header.",
                        "Consider enabling HSTS after confirming HTTPS is consistently configured on all relevant subdomains.",
                        final_url)
        if not headers.get("content_security_policy"):
            add_finding("low", "missing_csp", "Content-Security-Policy header was not detected",
                        "The response did not include a Content-Security-Policy header.",
                        "Design and test a restrictive CSP that matches the site's scripts, styles, images and integrations.",
                        final_url)

        for href in (page.get("links") or [])[:120]:
            absolute = urljoin(final_url, str(href))
            absolute, _ = urldefrag(absolute)
            parsed = urlparse(absolute)
            if parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower() == root_host:
                if absolute not in seen and absolute not in queue and len(seen) + len(queue) < max_pages * 4:
                    queue.append(absolute)

    if not pages:
        raise ValueError("No pages could be checked.")

    title_counts = Counter((str(x.get("title") or "").strip().casefold()) for x in pages if x.get("title"))
    for duplicate_title, count in title_counts.items():
        if count > 1:
            add_finding("low", "duplicate_titles", "Duplicate page titles were detected",
                        str(count) + " checked pages share the same title.",
                        "Give each important page a distinct title that reflects its unique purpose.",
                        root_url, duplicate_title[:180])

    severity_counts = Counter(x["severity"] for x in findings)
    score = max(0, 100 - severity_counts["high"] * 15 - severity_counts["medium"] * 8 - severity_counts["low"] * 3)
    return {
        "url": root_url,
        "checked_at": None,
        "pages_checked": len(pages),
        "pages_limit": max_pages,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "http_status": root.get("http_status"),
        "title": root.get("title"),
        "has_viewport_meta": root.get("has_viewport_meta"),
        "has_meta_description": root.get("has_meta_description"),
        "has_h1": root.get("has_h1"),
        "has_form": root.get("has_form"),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "health_score": score,
        },
        "pages": pages,
        "scope_note": (
            "Bounded public-page audit only. MCAS does not execute JavaScript, submit forms, sign in, test private APIs, "
            "scan ports, exploit vulnerabilities, verify business ownership, or provide a penetration-test certification. "
            "SPA and content rendered only in a browser may require a separate browser-based review."
        ),
    }
