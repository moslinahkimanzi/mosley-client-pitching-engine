"""Evidence-based static website audit helpers for MCAS.

This module performs bounded, non-invasive checks on a fetched public HTML page.
It is not a browser/Lighthouse scanner, vulnerability scanner, or penetration test.
"""
from html.parser import HTMLParser
from urllib.parse import urlparse
import re


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.in_title = False
        self.meta = {}
        self.images = []
        self.headings = []
        self.links = []
        self.forms = 0
        self.buttons = 0
        self.scripts = 0
        self.stylesheets = 0
        self.text_parts = []
        self.lang = ""
        self.canonical = False
        self.json_ld = False
        self.robots = ""

    def handle_starttag(self, tag, attrs):
        a = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "html":
            self.lang = a.get("lang", "")
        elif tag == "title":
            self.in_title = True
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or "").lower()
            if key:
                self.meta[key] = a.get("content", "")
            if key == "robots":
                self.robots = a.get("content", "")
        elif tag == "link":
            if "canonical" in a.get("rel", "").lower().split():
                self.canonical = bool(a.get("href"))
            if "stylesheet" in a.get("rel", "").lower().split():
                self.stylesheets += 1
        elif tag == "img":
            self.images.append({"alt": a.get("alt"), "src": a.get("src", "")})
        elif tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings.append(tag)
        elif tag == "a":
            self.links.append({"href": a.get("href", ""), "text": ""})
        elif tag == "form":
            self.forms += 1
        elif tag in {"button"} or (tag == "input" and a.get("type", "").lower() in {"submit", "button"}):
            self.buttons += 1
        elif tag == "script":
            self.scripts += 1
            if "ld+json" in a.get("type", "").lower():
                self.json_ld = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return
        if self.in_title:
            self.title_parts.append(text)
        self.text_parts.append(text)
        if self.links:
            self.links[-1]["text"] = (self.links[-1]["text"] + " " + text).strip()[:180]


def _score(checks):
    passed = sum(1 for item in checks if item["status"] == "pass")
    applicable = len(checks)
    return round((passed / applicable) * 100) if applicable else 0


def analyze_document(document, response_headers, page_url):
    parser = _PageParser()
    try:
        parser.feed(document[:512000])
    except Exception:
        pass
    headers = {str(k).lower(): str(v) for k, v in (response_headers or {}).items()}
    title = " ".join(parser.title_parts).strip()[:180] or None
    description = parser.meta.get("description", "").strip()
    viewport = bool(parser.meta.get("viewport"))
    h1_count = parser.headings.count("h1")
    missing_alt = sum(1 for image in parser.images if not str(image.get("alt") or "").strip())
    word_count = len(re.findall(r"\b[\w'-]+\b", " ".join(parser.text_parts)))
    page_host = (urlparse(page_url).hostname or "").lower()
    internal_links = 0
    contact_links = 0
    privacy_links = 0
    for link in parser.links:
        href = str(link.get("href") or "").strip()
        low = href.lower()
        if low.startswith(("mailto:", "tel:")):
            contact_links += 1
        if any(word in low for word in ("privacy", "data-protection")):
            privacy_links += 1
        if href.startswith("/") or (urlparse(href).hostname or "").lower() == page_host:
            internal_links += 1
    cta_count = sum(
        1 for link in parser.links
        if any(word in (link.get("text", "") + " " + link.get("href", "")).lower()
               for word in ("contact", "book", "reserve", "order", "quote", "enquir", "call", "buy"))
    ) + parser.buttons
    https = page_url.lower().startswith("https://")
    security_checks = [
        ("HTTPS transport", https, "Page was fetched over HTTPS." if https else "Page URL uses HTTP; transport is not encrypted."),
        ("HSTS", "strict-transport-security" in headers, "Strict-Transport-Security response header." if "strict-transport-security" in headers else "HSTS response header not observed."),
        ("Content Security Policy", "content-security-policy" in headers, "CSP response header observed." if "content-security-policy" in headers else "CSP response header not observed."),
        ("Clickjacking protection", "x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", ""), "Frame embedding restriction observed." if ("x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", "")) else "No X-Frame-Options or CSP frame-ancestors directive observed."),
        ("MIME sniffing protection", headers.get("x-content-type-options", "").lower() == "nosniff", "nosniff header observed." if headers.get("x-content-type-options", "").lower() == "nosniff" else "X-Content-Type-Options: nosniff not observed."),
        ("Referrer policy", "referrer-policy" in headers, "Referrer-Policy response header observed." if "referrer-policy" in headers else "Referrer-Policy response header not observed."),
    ]
    seo_checks = [
        ("Page title", bool(title), "Title: " + title if title else "No page title detected."),
        ("Meta description", bool(description), "Meta description detected." if description else "No meta description detected."),
        ("Single primary heading", h1_count == 1, str(h1_count) + " H1 element(s) detected; one clear H1 is usually preferable."),
        ("Canonical URL", parser.canonical, "Canonical link detected." if parser.canonical else "No canonical link detected."),
        ("Open Graph metadata", bool(parser.meta.get("og:title") and parser.meta.get("og:description")), "Basic Open Graph title and description detected." if (parser.meta.get("og:title") and parser.meta.get("og:description")) else "Open Graph title/description incomplete."),
        ("Readable page content", word_count >= 100, str(word_count) + " visible text words detected; check whether the page explains the offer clearly."),
        ("Structured data", parser.json_ld, "JSON-LD structured data detected." if parser.json_ld else "No JSON-LD structured data detected."),
    ]
    mobile_checks = [
        ("Viewport metadata", viewport, "Responsive viewport metadata detected." if viewport else "Viewport metadata not detected."),
        ("Mobile content volume", word_count >= 40, "Text content is present." if word_count >= 40 else "Very little text was detected; check mobile usefulness."),
    ]
    accessibility_checks = [
        ("Image alternative text", missing_alt == 0, str(missing_alt) + " image(s) missing detectable alt text."),
        ("Document language", bool(parser.lang), "HTML language is " + parser.lang + "." if parser.lang else "HTML lang attribute not detected."),
        ("Heading structure", bool(parser.headings) and parser.headings[0] == "h1", "Heading sequence starts with H1." if parser.headings and parser.headings[0] == "h1" else "No leading H1 detected; review heading hierarchy."),
    ]
    conversion_checks = [
        ("Clear action elements", cta_count > 0, str(cta_count) + " possible CTA element(s) detected; verify clarity and placement."),
        ("Contact pathway", contact_links > 0 or parser.forms > 0, "Contact link or form detected." if contact_links or parser.forms else "No obvious contact link or form detected."),
        ("Internal navigation", internal_links >= 3, str(internal_links) + " internal link(s) detected; review navigation completeness."),
    ]
    trust_checks = [
        ("Privacy information", privacy_links > 0, "Privacy-related link detected." if privacy_links else "No privacy-related link detected."),
        ("Business contact path", contact_links > 0, "Email/telephone link detected." if contact_links else "No mailto/tel link detected."),
        ("Cookie security flags", False, "Cookie flags cannot be reliably assessed by this bounded page fetch; verify Set-Cookie attributes in a browser/proxy test."),
    ]
    categories = {
        "seo": seo_checks,
        "mobile": mobile_checks,
        "accessibility": accessibility_checks,
        "conversion": conversion_checks,
        "trust": trust_checks,
        "transport_security_headers": security_checks,
    }
    scores = {name: _score(checks) for name, checks in categories.items()}
    findings = []
    for category, checks in categories.items():
        for item in checks:
            if item["status"] == "fail":
                findings.append({"category": category, "title": item["name"], "evidence": item["evidence"],
                                 "priority": "high" if category == "transport_security_headers" and item["name"] in {"HTTPS transport", "Content Security Policy"} else "medium"})
    # Avoid declaring absent headers or HTML markers to be exploitable vulnerabilities.
    for group in categories.values():
        for item in group:
            item["status"] = "pass" if item["status"] == "pass" else "review"
    return {
        "scores": scores,
        "overall_score": round(sum(scores.values()) / len(scores)),
        "categories": categories,
        "findings": findings[:40],
        "observations": {
            "title": title, "meta_description_present": bool(description), "viewport_present": viewport,
            "h1_count": h1_count, "image_count": len(parser.images), "images_missing_alt": missing_alt,
            "form_count": parser.forms, "possible_cta_count": cta_count, "word_count": word_count,
            "html_language": parser.lang or None, "robots_meta": parser.robots or None,
            "canonical_present": parser.canonical, "json_ld_present": parser.json_ld,
        },
        "limitations": [
            "Static HTML and response-header inspection only; JavaScript-rendered content may be missed.",
            "Not a Lighthouse/Core Web Vitals measurement, accessibility conformance test, malware scan, or penetration test.",
            "A missing header or HTML marker is a review item, not proof of an exploitable vulnerability.",
            "Verify every finding manually before presenting it to a business.",
        ],
    }
