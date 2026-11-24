"""Bounded, safe and evidence-oriented public website audit engine.

The crawler is deliberately non-invasive: it does not execute JavaScript, submit forms,
authenticate to the target, scan ports or attempt exploitation. Findings are aggregated
by stable issue code so the same issue on many pages is counted once in the score.
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from urllib.parse import urljoin, urlparse, urldefrag


CLASS_DETECTED = "detected_defect"
CLASS_RISK = "potential_risk"
CLASS_RECOMMENDATION = "recommendation"
CLASS_UNVERIFIED = "unverified_observation"

_DETECTED_CODES = {
    "https_not_used",
    "mixed_content",
    "missing_viewport",
    "missing_title",
    "missing_meta_description",
    "missing_h1",
    "missing_html_lang",
    "images_missing_alt",
    "duplicate_titles",
}
_RISK_CODES = {"missing_hsts", "missing_csp"}
_UNVERIFIED_CODES = {
    "form_controls_without_label",
    "slow_response",
    "page_fetch_failed",
    "external_redirect_not_crawled",
    "non_html_page",
}


def _classification_for(code: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    if code in _DETECTED_CODES:
        return CLASS_DETECTED
    if code in _RISK_CODES:
        return CLASS_RISK
    if code in _UNVERIFIED_CODES:
        return CLASS_UNVERIFIED
    return CLASS_UNVERIFIED


def _score_findings(findings: list[dict]) -> int:
    """Score unique, classified issues; recommendations and unverified observations do not penalise."""
    penalties = {
        CLASS_DETECTED: {"high": 15, "medium": 7, "low": 2},
        CLASS_RISK: {"high": 8, "medium": 4, "low": 1},
    }
    penalty = sum(
        penalties.get(item["classification"], {}).get(item["severity"], 0)
        for item in findings
    )
    return max(0, 100 - penalty)


def build_improvement_opportunities(findings: list[dict]) -> list[dict]:
    """Create deterministic opportunities from observed audit codes; no AI-generated claims."""
    by_code = {item["code"]: item for item in findings}
    rules = [
        {
            "id": "secure_delivery",
            "codes": {"https_not_used", "mixed_content", "missing_hsts", "missing_csp"},
            "title": "Secure delivery and asset remediation",
            "priority": "high",
            "description": "Review the HTTPS delivery path, insecure resource references and response security-header configuration.",
            "scope": [
                "Replace HTTP resource references with valid HTTPS URLs and confirm that each resource loads.",
                "Confirm HTTPS redirects and certificate coverage across relevant hostnames.",
                "Design and stage-test HSTS and Content-Security-Policy settings before enabling them broadly.",
            ],
        },
        {
            "id": "accessibility",
            "codes": {"images_missing_alt", "form_controls_without_label", "missing_html_lang"},
            "title": "Accessibility and inclusive-use improvements",
            "priority": "medium",
            "description": "Improve machine-readable page semantics and verify that key journeys work with assistive technology.",
            "scope": [
                "Add meaningful alt text to informative images and empty alt text to decorative images.",
                "Review form labels, accessible names, focus order and keyboard operation.",
                "Declare the page language and run a manual screen-reader review of important journeys.",
            ],
        },
        {
            "id": "search_foundations",
            "codes": {"missing_title", "missing_meta_description", "missing_h1", "duplicate_titles"},
            "title": "Search visibility and page metadata",
            "priority": "medium",
            "description": "Make important pages easier to distinguish and understand through unique titles, descriptions and headings.",
            "scope": [
                "Write a unique, accurate title and meta description for each important page.",
                "Use one clear primary H1 and a meaningful heading hierarchy where appropriate.",
                "Check canonical URLs and page indexing settings before publishing changes.",
            ],
        },
        {
            "id": "availability",
            "codes": {"http_not_found", "http_server_error", "page_fetch_failed"},
            "title": "Page availability and navigation review",
            "priority": "high",
            "description": "Investigate pages that returned errors or could not be checked during this bounded crawl.",
            "scope": [
                "Recheck the affected URL manually and confirm whether the response is intentional.",
                "Repair confirmed broken routes and update navigation links that point to unavailable pages.",
                "Review hosting, redirects and access rules for pages that remain inaccessible.",
            ],
        },
        {
            "id": "performance",
            "codes": {"slow_response"},
            "title": "Performance investigation",
            "priority": "medium",
            "description": "Repeat slow-response observations and measure real-user performance before selecting optimisations.",
            "scope": [
                "Repeat server response measurements from representative locations.",
                "Measure Core Web Vitals in a browser-based tool; this audit does not measure them.",
                "Review caching, server processing, image sizes and third-party resources.",
            ],
        },
    ]

    opportunities = []
    for rule in rules:
        matched = [by_code[code] for code in sorted(rule["codes"]) if code in by_code]
        if not matched:
            continue
        urls = []
        for finding in matched:
            for url in finding.get("affected_pages", []):
                if url not in urls:
                    urls.append(url)
        opportunities.append({
            "id": rule["id"],
            "classification": CLASS_RECOMMENDATION,
            "title": rule["title"],
            "priority": rule["priority"],
            "description": rule["description"],
            "recommended_scope": list(rule["scope"]),
            "related_finding_codes": [item["code"] for item in matched],
            "basis": "Derived from the audit findings listed in this report. Confirm scope and business requirements with the website owner.",
            "affected_pages": urls,
        })

    if not opportunities:
        opportunities.append({
            "id": "conversion_review",
            "classification": CLASS_RECOMMENDATION,
            "title": "Customer journey and conversion review",
            "priority": "low",
            "description": "The bounded checks did not identify one of the mapped technical improvement groups. A separate usability review may still identify opportunities.",
            "recommended_scope": [
                "Review whether visitors can quickly understand the business, services and next step.",
                "Test important mobile journeys with representative users.",
                "Confirm that contact, booking or enquiry routes match the business's current process.",
            ],
            "related_finding_codes": [],
            "basis": "Strategic recommendation only; the static audit did not verify a conversion problem.",
            "affected_pages": [],
        })
    return opportunities


def advanced_site_audit(initial_url: str, fetcher, max_pages: int = 10) -> dict:
    """Crawl a small number of same-host public HTML pages using an SSRF-safe fetcher."""
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
    findings_by_code: dict[str, dict] = {}
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3}

    def add_finding(
        severity: str,
        code: str,
        title: str,
        description: str,
        recommendation: str,
        url: str | None = None,
        evidence: str | None = None,
        classification: str | None = None,
        affected_urls: list[str] | None = None,
    ):
        """Merge occurrences of a single issue code without discarding page-level proof."""
        issue_class = _classification_for(code, classification)
        finding = findings_by_code.get(code)
        if finding is None:
            finding = {
                "severity": severity,
                "code": code,
                "title": title,
                "description": description,
                "recommendation": recommendation,
                "classification": issue_class,
                "url": url,
                "affected_pages": [],
                "evidence_by_page": [],
                "page_count": 0,
            }
            findings_by_code[code] = finding
        elif severity_rank.get(severity, 0) > severity_rank.get(finding["severity"], 0):
            finding["severity"] = severity

        urls = list(affected_urls or [])
        if url and url not in urls:
            urls.insert(0, url)
        for page_url in urls:
            if page_url and page_url not in finding["affected_pages"]:
                finding["affected_pages"].append(page_url)
        if evidence:
            evidence_text = str(evidence)[:500]
            evidence_urls = urls or [None]
            for evidence_url in evidence_urls:
                entry = {"url": evidence_url, "detail": evidence_text}
                if entry not in finding["evidence_by_page"]:
                    finding["evidence_by_page"].append(entry)
        finding["page_count"] = len(finding["affected_pages"])
        finding["url"] = finding["affected_pages"][0] if finding["affected_pages"] else finding["url"]
        # Keep the legacy single evidence field for older UI/API consumers.
        evidence_details = [item["detail"] for item in finding["evidence_by_page"]]
        finding["evidence"] = "; ".join(dict.fromkeys(evidence_details))[:1000] or None

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
                error_detail = str(getattr(exc, "detail", "The page could not be checked safely"))[:180]
                pages.append({
                    "url": requested,
                    "http_status": None,
                    "title": None,
                    "response_time_ms": None,
                    "error": error_detail,
                })
                add_finding(
                    "medium", "page_fetch_failed", "An internal page could not be checked",
                    "A same-host link could not be fetched by the bounded public-page checker.",
                    "Open the link manually and confirm whether it is intentionally restricted, moved or unavailable.",
                    requested, error_detail, CLASS_UNVERIFIED,
                )
                continue

        final_url = page.get("url") or requested
        final_host = (urlparse(final_url).hostname or "").lower()
        if final_host != root_host:
            pages.append({
                "url": requested, "http_status": page.get("http_status"), "title": page.get("title"),
                "response_time_ms": page.get("response_time_ms"), "redirected_off_host": True,
            })
            add_finding(
                "info", "external_redirect_not_crawled", "A page redirected to another host",
                "MCAS stopped crawling after the redirect left the starting hostname.",
                "Review the redirect destination manually; external hosts are not included in this crawl.",
                requested, final_url, CLASS_UNVERIFIED,
            )
            continue

        status = page.get("http_status")
        title = page.get("title")
        content_type = str(page.get("content_type") or "").lower()
        is_html = "html" in content_type or page.get("has_viewport_meta") is not None
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

        try:
            numeric_status = int(status) if status is not None else None
        except (TypeError, ValueError):
            numeric_status = None
        if numeric_status is not None and numeric_status >= 400:
            if numeric_status in {404, 410}:
                add_finding(
                    "medium", "http_not_found", "A public page returned a not-found response",
                    "The checked URL returned HTTP " + str(numeric_status) + ". Confirm whether the route should exist and be publicly reachable.",
                    "Confirm the URL, repair or redirect a genuinely missing route, and update links that point to it.",
                    final_url, "HTTP " + str(numeric_status), CLASS_DETECTED,
                )
            elif numeric_status >= 500:
                add_finding(
                    "high", "http_server_error", "A public page returned a server-error response",
                    "The checked URL returned HTTP " + str(numeric_status) + ". A single response does not establish whether the failure is persistent.",
                    "Repeat the request, inspect hosting and application logs, and confirm whether the server error persists.",
                    final_url, "HTTP " + str(numeric_status), CLASS_DETECTED,
                )
            elif numeric_status in {401, 403, 429}:
                add_finding(
                    "info", "http_access_restricted", "A page response requires access review",
                    "The URL returned an authentication, access-control or rate-limit response. This may be intentional and does not prove a broken page.",
                    "Confirm whether the page is intended to be public; repeat the check through an authorised browser session where appropriate.",
                    final_url, "HTTP " + str(numeric_status), CLASS_UNVERIFIED,
                )
            else:
                add_finding(
                    "info", "http_response_unverified", "A page returned a client-error response",
                    "The URL returned HTTP " + str(numeric_status) + ". The static check cannot determine whether this response is intentional or indicates a user-facing defect.",
                    "Manually review the URL and reproduce the request using the website's normal user journey.",
                    final_url, "HTTP " + str(numeric_status), CLASS_UNVERIFIED,
                )
            continue

        if not is_html:
            add_finding(
                "info", "non_html_page", "A checked URL was not an HTML page",
                "The response was not HTML, so page structure and metadata could not be analysed.",
                "Review non-HTML resources separately if they are important to the customer journey.",
                final_url, str(page.get("content_type") or "Content type not supplied"),
                CLASS_UNVERIFIED,
            )
            continue

        if not item["https"]:
            add_finding(
                "high", "https_not_used", "The page is not served over HTTPS",
                "The checked page URL uses plain HTTP.",
                "Configure HTTPS with a valid certificate and redirect HTTP requests to HTTPS.",
                final_url, "URL scheme: http", CLASS_DETECTED,
            )
        if page.get("has_viewport_meta") is False:
            add_finding(
                "medium", "missing_viewport", "Mobile viewport metadata was not detected",
                "The checked HTML page did not expose a viewport meta tag.",
                "Add a responsive viewport declaration and test the actual layout on mobile devices.",
                final_url, classification=CLASS_DETECTED,
            )
        if not title:
            add_finding(
                "medium", "missing_title", "The page title was not detected",
                "The checked HTML page did not expose a non-empty title element.",
                "Add a unique, descriptive title that accurately reflects the page content.",
                final_url, classification=CLASS_DETECTED,
            )
        if page.get("has_meta_description") is False:
            add_finding(
                "low", "missing_meta_description", "Meta description was not detected",
                "The checked HTML page did not expose a meta description.",
                "Add a concise, page-specific description that accurately summarises the content.",
                final_url, classification=CLASS_DETECTED,
            )
        if page.get("has_h1") is False:
            add_finding(
                "low", "missing_h1", "A main H1 heading was not detected",
                "The checked HTML page did not expose an H1 element.",
                "Use a clear primary heading and a meaningful heading hierarchy where appropriate.",
                final_url, classification=CLASS_DETECTED,
            )
        if page.get("has_lang") is False:
            add_finding(
                "low", "missing_html_lang", "HTML document language was not declared",
                "The root HTML element did not expose a lang attribute.",
                "Set the document language, for example lang=\"en\", to support assistive technology.",
                final_url, classification=CLASS_DETECTED,
            )
        missing_alt = int(page.get("images_missing_alt") or 0)
        if missing_alt:
            add_finding(
                "medium", "images_missing_alt", "Images without alt attributes were detected",
                "One or more inspected image elements lacked an alt attribute.",
                "Add meaningful alternative text to informative images and empty alt text to decorative images.",
                final_url,
                str(missing_alt) + " of " + str(page.get("images_total") or 0) + " inspected image element(s) lacked an alt attribute.",
                CLASS_DETECTED,
            )
        unlabelled = int(page.get("form_controls_without_label") or 0)
        if unlabelled:
            add_finding(
                "medium", "form_controls_without_label", "Some form controls may lack accessible labels",
                "A static check did not find a directly associated label, aria-label or aria-labelledby for some controls. Implicit labels and browser-rendered states may not be fully represented.",
                "Manually verify accessible names, associated labels, keyboard operation and screen-reader output for each form.",
                final_url, str(unlabelled) + " form control(s) flagged by the static label check.",
                CLASS_UNVERIFIED,
            )
        mixed = int(page.get("mixed_content_references") or 0)
        if mixed and item["https"]:
            add_finding(
                "high", "mixed_content", "HTTP resources were referenced by an HTTPS page",
                "The inspected HTTPS page references one or more resources using plain HTTP.",
                "Serve all page resources over HTTPS and remove insecure resource references; verify each resource loads after the change.",
                final_url, str(mixed) + " mixed-content reference(s)", CLASS_DETECTED,
            )
        try:
            response_time = float(page.get("response_time_ms") or 0)
        except (TypeError, ValueError):
            response_time = 0
        if response_time > 3000:
            add_finding(
                "low", "slow_response", "A slow response was observed during this check",
                "This single request exceeded three seconds. Network conditions, caching and temporary server load can affect the observation.",
                "Repeat the measurement from representative locations and measure browser-based Core Web Vitals before choosing an optimisation.",
                final_url, str(round(response_time)) + " ms", CLASS_UNVERIFIED,
            )
        headers = page.get("security_headers") or {}
        if item["https"] and not headers.get("strict_transport_security"):
            add_finding(
                "low", "missing_hsts", "Strict-Transport-Security header was not detected",
                "The response did not include an HSTS response header. This is a hardening opportunity, not proof of an exploitable vulnerability.",
                "Consider enabling HSTS after confirming HTTPS is consistently configured on all relevant subdomains.",
                final_url, classification=CLASS_RISK,
            )
        if not headers.get("content_security_policy"):
            add_finding(
                "low", "missing_csp", "Content-Security-Policy header was not detected",
                "The response did not include a Content-Security-Policy header. Its absence alone does not establish exploitability.",
                "Design and stage-test a restrictive CSP that matches the site's scripts, styles, images and integrations.",
                final_url, classification=CLASS_RISK,
            )

        for href in (page.get("links") or [])[:120]:
            absolute = urljoin(final_url, str(href))
            absolute, _fragment = urldefrag(absolute)
            parsed = urlparse(absolute)
            if parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower() == root_host:
                if absolute not in seen and absolute not in queue and len(seen) + len(queue) < max_pages * 4:
                    queue.append(absolute)

    if not pages:
        raise ValueError("No pages could be checked.")

    title_to_pages = defaultdict(list)
    for page in pages:
        page_title = str(page.get("title") or "").strip()
        if page_title and not page.get("error") and not page.get("redirected_off_host"):
            title_to_pages[page_title.casefold()].append(page)
    for duplicate_title, matching_pages in title_to_pages.items():
        if len(matching_pages) > 1:
            duplicate_urls = [page["url"] for page in matching_pages]
            add_finding(
                "low", "duplicate_titles", "Duplicate page titles were detected",
                str(len(matching_pages)) + " checked pages share the same title.",
                "Give each important page a distinct title that reflects its unique purpose.",
                duplicate_urls[0], duplicate_title[:180], CLASS_DETECTED, duplicate_urls,
            )

    findings = list(findings_by_code.values())
    for finding in findings:
        finding["affected_pages"] = finding["affected_pages"][:15]
        finding["evidence_by_page"] = finding["evidence_by_page"][:30]
        finding["page_count"] = len(finding["affected_pages"])

    severity_counts = Counter(item["severity"] for item in findings)
    classification_counts = Counter(item["classification"] for item in findings)
    opportunities = build_improvement_opportunities(findings)
    score = _score_findings(findings)

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
        "findings": findings,
        "recommendations": opportunities,
        "summary": {
            "total": len(findings),
            "unique_findings": len(findings),
            "page_occurrences": sum(item["page_count"] for item in findings),
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "detected_defects": classification_counts[CLASS_DETECTED],
            "potential_risks": classification_counts[CLASS_RISK],
            "recommendations": len(opportunities),
            "unverified_observations": classification_counts[CLASS_UNVERIFIED],
            "health_score": score,
            "score_method": "Unique issue codes are counted once across all checked pages. Detected defects and potential risks affect the score; recommendations and unverified observations do not.",
        },
        "score_disclaimer": "The health score is a prioritisation indicator for the issues this bounded static audit detected. It is not a security rating, accessibility certification, search ranking prediction or proof that untested areas are healthy.",
        "pages": pages,
        "limitations": [
            "Only a bounded number of publicly linked pages on the starting hostname were inspected; other routes and subdomains may not be included.",
            "JavaScript-rendered, browser-only, authenticated and personalised content may not be visible in the fetched HTML.",
            "Response-time observations are individual server requests, not Core Web Vitals or representative real-user performance measurements.",
            "Static accessibility signals are not a WCAG conformance audit; keyboard, screen-reader and user testing remain necessary.",
            "Missing HSTS or Content-Security-Policy headers are hardening observations, not proof of an exploitable vulnerability.",
            "MCAS does not scan ports, exploit vulnerabilities, submit forms, test private APIs or provide penetration-test certification.",
        ],
        "scope_note": (
            "Bounded public-page audit only. MCAS does not execute JavaScript, submit forms, sign in, test private APIs, "
            "scan ports, exploit vulnerabilities, verify business ownership, or provide a penetration-test certification. "
            "SPA and content rendered only in a browser may require a separate browser-based review."
        ),
    }
