"""Google OpenID Connect ID-token verification for MCAS sign-in."""
from __future__ import annotations

import base64
import json
import time
import urllib.request
import urllib.error
import hmac
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_JWKS_CACHE: dict[str, Any] = {"expires": 0, "keys": []}


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _google_jwks() -> list[dict]:
    now = time.time()
    if _JWKS_CACHE["expires"] > now and _JWKS_CACHE["keys"]:
        return _JWKS_CACHE["keys"]
    request = urllib.request.Request(
        "https://www.googleapis.com/oauth2/v3/certs",
        headers={"Accept": "application/json", "User-Agent": "MCAS/1.0 Google OIDC verifier"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read(200_000))
        keys = data.get("keys", [])
        if not isinstance(keys, list) or not keys:
            raise ValueError("Google returned no public signing keys")
    except Exception as exc:
        raise ValueError("Google signing keys could not be retrieved") from exc
    _JWKS_CACHE["keys"] = keys
    _JWKS_CACHE["expires"] = now + 3600
    return keys


def verify_google_id_token(id_token: str, client_id: str, expected_nonce_hash: str) -> dict:
    """Verify Google RS256 signature and critical OIDC claims before trusting identity."""
    if not isinstance(id_token, str) or len(id_token) > 20_000:
        raise ValueError("Google returned an invalid ID token")
    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("Google returned a malformed ID token")
    try:
        header = json.loads(_b64url(parts[0]))
        claims = json.loads(_b64url(parts[1]))
        signature = _b64url(parts[2])
    except Exception as exc:
        raise ValueError("Google returned a malformed ID token") from exc

    if header.get("alg") != "RS256" or not header.get("kid"):
        raise ValueError("Google ID token used an unsupported signing algorithm")
    jwk = next((item for item in _google_jwks() if item.get("kid") == header.get("kid")
                and item.get("kty") == "RSA" and item.get("alg", "RS256") == "RS256"), None)
    if not jwk:
        _JWKS_CACHE["expires"] = 0
        jwk = next((item for item in _google_jwks() if item.get("kid") == header.get("kid")
                    and item.get("kty") == "RSA" and item.get("alg", "RS256") == "RS256"), None)
    if not jwk:
        raise ValueError("Google signing key was not recognised")

    try:
        n = int.from_bytes(_b64url(jwk["n"]), "big")
        e = int.from_bytes(_b64url(jwk["e"]), "big")
        public_key = rsa.RSAPublicNumbers(e, n).public_key()
        public_key.verify(
            signature,
            (parts[0] + "." + parts[1]).encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise ValueError("Google ID token signature is invalid") from exc

    now = int(time.time())
    issuer = claims.get("iss")
    if issuer not in {"https://accounts.google.com", "accounts.google.com"}:
        raise ValueError("Google ID token issuer is invalid")
    aud = claims.get("aud")
    if aud != client_id and not (isinstance(aud, list) and client_id in aud):
        raise ValueError("Google ID token audience does not match this application")
    if isinstance(aud, list) and claims.get("azp") != client_id:
        raise ValueError("Google ID token authorised party is invalid")
    if claims.get("azp") not in (None, client_id):
        raise ValueError("Google ID token authorised party is invalid")
    try:
        exp = int(claims.get("exp", 0))
        issued = int(claims.get("iat", 0))
    except (TypeError, ValueError):
        raise ValueError("Google ID token timestamps are invalid")
    if exp <= now or issued > now + 60 or issued < now - 3600:
        raise ValueError("Google ID token has expired or is outside the accepted time window")
    nonce = str(claims.get("nonce", ""))
    if not nonce or not hmac.compare_digest(
        __import__("hashlib").sha256(nonce.encode()).hexdigest(), expected_nonce_hash
    ):
        raise ValueError("Google sign-in nonce is invalid")
    if claims.get("email_verified") not in (True, "true", "True"):
        raise ValueError("Google account email is not verified")
    email = str(claims.get("email", "")).strip().lower()
    subject = str(claims.get("sub", "")).strip()
    if not email or "@" not in email or not subject:
        raise ValueError("Google account did not provide a valid email identity")
    return {
        "sub": subject,
        "email": email,
        "name": str(claims.get("name", ""))[:160],
        "picture": str(claims.get("picture", ""))[:1000],
    }
