"""Deterministic, evidence-based prospect verification for MCAS.

This module does not claim legal identity verification, proof of current trading,
email deliverability, consent to marketing, or buying intent. It requires a
structured Places record plus a corroborating public website or web result.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit


_COUNTRY_AND_ADMIN_WORDS = {
    "county", "city", "town", "municipality", "district", "province",
    "region", "ward", "subcounty", "sub-county", "kenya", "uganda",
    "tanzania", "rwanda", "burundi", "somalia", "ethiopia", "nigeria",
    "ghana", "south", "east", "west", "north", "central",
}
_NAME_NOISE = {
    "the", "and", "of", "limited", "ltd", "plc", "inc", "incorporated",
    "company", "co", "corporation", "corp", "llc", "llp",
}
_NON_CORROBORATING_HOSTS = (
    "google.com", "google.co.ke", "googleusercontent.com", "gstatic.com",
    "googleapis.com", "serper.dev", "facebook.com", "instagram.com",
    "linkedin.com", "youtube.com", "tiktok.com", "twitter.com", "x.com",
    "whatsapp.com", "wa.me",
)


def normalise_text(value: object) -> str:
    """Fold accents, punctuation and spacing for deterministic text comparison."""
    raw = unicodedata.normalize("NFKD", str(value or ""))
    raw = "".join(char for char in raw if not unicodedata.combining(char))
    return " ".join(re.findall(r"[a-z0-9]+", raw.casefold()))


def _name_tokens(value: object) -> list[str]:
    return [token for token in normalise_text(value).split()
            if token not in _NAME_NOISE and len(token) > 1]


def name_match_score(business_name: str, candidate_text: str) -> float:
    """Return a transparent token match ratio; this is not a probability."""
    expected = _name_tokens(business_name)
    actual = set(normalise_text(candidate_text).split())
    if not expected:
        return 0.0
    if len(expected) == 1:
        token = expected[0]
        return 1.0 if token in actual and len(token) >= 4 else 0.0
    matched = sum(1 for token in expected if token in actual)
    if matched == len(expected):
        return 1.0
    return matched / len(expected)


def _host(value: object) -> str:
    try:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        return parsed.hostname.casefold().rstrip(".").removeprefix("www.")
    except (TypeError, ValueError):
        return ""


def _is_acceptable_source_host(host: str) -> bool:
    if not host:
        return False
    return not any(host == blocked or host.endswith("." + blocked)
                   for blocked in _NON_CORROBORATING_HOSTS)


def _location_tokens(location: str, address: str) -> set[str]:
    location_tokens = {
        token for token in normalise_text(location).split()
        if len(token) >= 3 and token not in _COUNTRY_AND_ADMIN_WORDS
    }
    address_tokens = {
        token for token in normalise_text(address).split()
        if len(token) >= 4 and token not in _COUNTRY_AND_ADMIN_WORDS
    }
    return location_tokens | address_tokens


# These hosts can help corroborate that a business exists, but they are not
# treated as the business's own website when searching for an official domain.
_NON_WEBSITE_HOSTS = _NON_CORROBORATING_HOSTS + (
    "yelp.com", "tripadvisor.com", "yellowpages.com", "foursquare.com",
    "mapquest.com", "hotfrog.com", "booking.com", "expedia.com",
    "opentable.com", "ubereats.com", "doordash.com", "glovoapp.com",
    "justdial.com", "trustpilot.com", "zomato.com", "deliveroo.com",
)


def find_business_website_candidate(
    business_name: str,
    location: str,
    address: str,
    web_results: list[dict] | None = None,
) -> str | None:
    """Find a likely first-party domain in corroborating search results.

    This is only a candidate URL. Callers must fetch it and validate the
    returned page/domain before classifying the business as having a website.
    Directory, booking, review and social platforms are deliberately excluded.
    """
    candidates = []
    locality_tokens = _location_tokens(location, address)
    for result in web_results or []:
        if not isinstance(result, dict):
            continue
        link = result.get("link") or result.get("url")
        host = _host(link)
        if not link or not host:
            continue
        if any(host == blocked or host.endswith("." + blocked)
               for blocked in _NON_WEBSITE_HOSTS):
            continue
        if any(marker in host for marker in ("directory", "listing", "review", "maps")):
            continue
        title = str(result.get("title") or "")
        snippet = str(result.get("snippet") or result.get("description") or "")
        match_text = title + " " + snippet
        name_score = name_match_score(business_name, match_text)
        locality_match = bool(locality_tokens & set(normalise_text(match_text).split()))
        host_tokens = set(re.findall(r"[a-z0-9]+", host))
        distinctive_name_tokens = {
            token for token in _name_tokens(business_name)
            if len(token) >= 4 and token not in {
                "restaurant", "restaurants", "hotel", "hotels", "salon",
                "cafe", "clinic", "medical", "school", "shop", "store",
                "services", "service", "group", "company", "business",
            }
        }
        # Require the domain itself to carry a distinctive business-name token.
        # This intentionally abstains when a search result could be a directory,
        # news article or unrelated third-party profile.
        domain_name_match = bool(distinctive_name_tokens & host_tokens)
        if name_score < 0.8 or not locality_match or not domain_name_match:
            continue
        candidates.append((name_score, len(snippet), str(link)))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def _phone_digits(value: object) -> str:
    return re.sub(r"\D", "", str(value or ""))


def _closed_status(place: dict) -> bool:
    values = [
        place.get("business_status"),
        place.get("businessStatus"),
        place.get("openState"),
        place.get("permanentlyClosed"),
    ]
    text = " ".join(str(value or "") for value in values).casefold()
    return bool(place.get("permanentlyClosed") is True or
                re.search(r"\b(permanently closed|closed permanently|permanently_closed|closed_permanently)\b", text))


def verify_candidate(
    place: dict,
    location: str,
    web_results: list[dict] | None = None,
    website: str | None = None,
    website_audit: dict | None = None,
    source_url: str = "",
) -> dict:
    """Assess a Places result against one or more public corroborating records.

    A record is auto-verified only when the Places result includes a name and
    address and either its listed website's title matches the business name or
    a distinct public web result matches both the business name and locality.
    """
    web_results = web_results or []
    website_audit = website_audit or {}
    name = str(place.get("title") or place.get("name") or "").strip()
    address = str(place.get("address") or "").strip()
    website_host = _host(website)
    title = str(website_audit.get("title") or "")
    title_score = name_match_score(name, title)
    website_identity_match = bool(
        website_host and _is_acceptable_source_host(website_host)
        and title_score >= 0.8
    )

    matched_sources: list[dict] = []
    matched_hosts: set[str] = set()
    combined_source_text = []
    for result in web_results:
        if not isinstance(result, dict):
            continue
        link = result.get("link") or result.get("url")
        host = _host(link)
        if not _is_acceptable_source_host(host):
            continue
        text = " ".join(str(result.get(key) or "")
                        for key in ("title", "snippet", "description"))
        name_score = name_match_score(name, text)
        text_tokens = set(normalise_text(text).split())
        locality_tokens = _location_tokens(location, address)
        locality_match = bool(locality_tokens & text_tokens)
        if name_score < 0.75 or not locality_match:
            continue
        if host in matched_hosts:
            continue
        matched_hosts.add(host)
        combined_source_text.append(text)
        matched_sources.append({
            "type": "public_web_result",
            "label": "Public page matches business name and locality",
            "url": str(link),
            "title": str(result.get("title") or "")[:200],
            "domain": host,
            "name_match": round(name_score, 2),
            "locality_match": True,
        })
        if len(matched_sources) >= 3:
            break

    has_place_identity = bool(name and len(_name_tokens(name)) >= 1 and address)
    is_closed = _closed_status(place)
    corroborated = website_identity_match or bool(matched_sources)
    verified = has_place_identity and corroborated and not is_closed

    score = 0
    reasons: list[str] = []
    if name:
        score += 15
        reasons.append("Structured Places result contains a business name.")
    if address:
        score += 20
        reasons.append("Structured Places result contains a street or locality address.")
    if matched_sources:
        score += 45
        reasons.append("At least one distinct public page matches the business name and locality.")
    if website_identity_match:
        score += 45
        reasons.append("The listed website's page title matches the business name.")
    if website and website_host and _is_acceptable_source_host(website_host):
        score += 5
    website_domain_corroborated = bool(website_host and website_host in matched_hosts)
    if website_domain_corroborated:
        reasons.append("An independent matching public result references the listed website domain.")

    all_public_text = " ".join(combined_source_text)
    listed_phone = _phone_digits(place.get("phoneNumber") or place.get("phone"))
    phone_corroborated = bool(
        len(listed_phone) >= 7 and
        any(listed_phone[-7:] in _phone_digits(text) for text in combined_source_text)
    )
    listed_email = str(place.get("email") or "").strip().casefold()
    email_corroborated = bool(
        listed_email and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", listed_email)
        and any(listed_email in text.casefold() for text in combined_source_text)
    )
    if phone_corroborated:
        score += 10
        reasons.append("The listed phone number also appears in a matching public result.")
    if email_corroborated:
        score += 10
        reasons.append("The listed email address also appears in a matching public result.")
    if is_closed:
        score = min(score, 30)
        reasons.append("The Places provider reports the business as permanently closed.")
        status = "closed"
    elif verified:
        score = max(score, 80)
        status = "verified"
    else:
        status = "not_verified"
        if not name:
            reasons.append("The discovery record has no usable business name.")
        if not address:
            reasons.append("The discovery record has no address; locality could not be corroborated.")
        if not corroborated:
            reasons.append("No matching external website or public page was found.")
    score = max(0, min(100, score))

    sources = [{
        "type": "places_listing",
        "label": "Structured Serper Places listing",
        "url": source_url,
        "domain": _host(source_url),
    }]
    if website_identity_match:
        sources.append({
            "type": "business_website",
            "label": "Listed website title matches business name",
            "url": str(website),
            "domain": website_host,
            "name_match": round(title_score, 2),
        })
    sources.extend(matched_sources)
    return {
        "status": status,
        "verified": verified,
        "evidence_score": score,
        "reasons": reasons,
        "sources": sources,
        "website_identity_match": website_identity_match,
        "website_domain_corroborated": website_domain_corroborated,
        "phone_corroborated": phone_corroborated,
        "email_corroborated": email_corroborated,
        "closed": is_closed,
        "definition": (
            "Auto-verified means a structured Places listing has a name and address "
            "and a matching listed website title or a distinct public page matching "
            "the name and locality. It does not prove current trading, ownership, "
            "contact deliverability, permission to market, or buying intent."
        ),
    }


def qualify_website_opportunity(
    verification: dict,
    website_state: str,
    website_audit: dict | None = None,
) -> tuple[bool, str]:
    """Require a verified identity and a reproducible, identity-linked website issue."""
    website_audit = website_audit or {}
    if verification.get("status") != "verified":
        return False, "business_identity_not_verified"
    if (website_state == "broken"
            and int(website_audit.get("confirmed_unavailable_checks") or 0) >= 2
            and (verification.get("website_identity_match") or verification.get("website_domain_corroborated"))):
        return True, "identity_linked_website_returned_404_or_410_twice"
    if website_state == "needs_improvement" and verification.get("website_identity_match"):
        missing = [
            key for key in ("has_viewport_meta", "has_meta_description")
            if website_audit.get(key) is False
        ]
        if website_audit.get("title") is None:
            missing.append("title")
        if missing:
            return True, "confirmed_homepage_metadata_gaps"
    if website_state == "not_listed":
        return False, "website_not_listed_is_not_proof_of_no_website"
    if website_state == "needs_review" or website_state == "access_restricted":
        return False, "website_condition_not_verified"
    return False, "no_material_website_issue_detected"
