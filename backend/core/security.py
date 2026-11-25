from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import quote, urlparse

import pyotp
from fastapi import HTTPException, status

from backend.db.pg import Tx


def get_admin_emails() -> set[str]:
    raw = os.environ.get("ADMIN_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


def is_unlimited_admin(user: dict[str, Any] | None) -> bool:
    if not user:
        return False
    email = str(user.get("email", "")).strip().lower()
    return bool(email and email in get_admin_emails())


def verify_admin_mfa(secret: str | None, code: str | None) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def validate_safe_external_url(raw_url: str) -> str:
    """Blocks SSRF attempts targeting localhost, private LANs, or cloud metadata IPs."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    hostname = parsed.hostname.lower()
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or hostname.endswith(".local"):
        raise HTTPException(status_code=400, detail="Local or internal hostnames are blocked")

    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail=f"Domain could not be resolved: {hostname}") from exc

    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        ip_obj = ipaddress.ip_address(ip_str)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise HTTPException(status_code=400, detail="Target IP resolves to a restricted network range")

    return url


async def get_owned_record(c: Tx, table: str, record_id: str, user_id: str) -> dict[str, Any]:
    """Enforces strict tenant ownership on every object lookup to prevent IDOR/BOLA."""
    allowed_tables = {
        "leads",
        "drafts",
        "followups",
        "proposals",
        "website_audit_reports",
    }
    if table not in allowed_tables:
        raise ValueError(f"Unsupported table lookup: {table}")

    row = await c.one(f"SELECT * FROM {table} WHERE id=? AND user_id=?", (record_id, user_id))
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")
    return row


def build_gmail_compose_url(to_email: str, subject: str, body: str) -> str:
    """Zero-OAuth fallback URL so users can open pre-filled drafts in Gmail immediately."""
    return (
        "https://google.com"
        f"&to={quote(to_email or '')}"
        f"&su={quote(subject or '')}"
        f"&body={quote(body or '')}"
    )
