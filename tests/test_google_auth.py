import base64
import hashlib
import json
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from backend.google_auth import verify_google_id_token


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class GoogleOIDCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = cls.private_key.public_key().public_numbers()
        cls.jwk = {
            "kid": "mcas-test-key", "kty": "RSA", "alg": "RS256",
            "n": b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
        }

    def token(self, nonce="one-time-nonce", email_verified=True):
        header = {"alg": "RS256", "kid": "mcas-test-key", "typ": "JWT"}
        claims = {
            "iss": "https://accounts.google.com", "aud": "mcas-client",
            "exp": int(time.time()) + 300, "iat": int(time.time()),
            "sub": "google-subject-123", "email": "owner@example.test",
            "email_verified": email_verified, "nonce": nonce,
        }
        body = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + b64url(
            json.dumps(claims, separators=(",", ":")).encode()
        )
        signature = self.private_key.sign(body.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return body + "." + b64url(signature)

    @patch("backend.google_auth._google_jwks")
    def test_valid_google_token_is_verified(self, jwks):
        jwks.return_value = [self.jwk]
        nonce = "one-time-nonce"
        identity = verify_google_id_token(
            self.token(nonce=nonce), "mcas-client", hashlib.sha256(nonce.encode()).hexdigest()
        )
        self.assertEqual(identity["email"], "owner@example.test")
        self.assertEqual(identity["sub"], "google-subject-123")

    @patch("backend.google_auth._google_jwks")
    def test_unverified_email_is_rejected(self, jwks):
        jwks.return_value = [self.jwk]
        nonce = "one-time-nonce"
        with self.assertRaises(ValueError):
            verify_google_id_token(
                self.token(nonce=nonce, email_verified=False),
                "mcas-client", hashlib.sha256(nonce.encode()).hexdigest()
            )

    @patch("backend.google_auth._google_jwks")
    def test_wrong_audience_is_rejected(self, jwks):
        jwks.return_value = [self.jwk]
        nonce = "one-time-nonce"
        with self.assertRaises(ValueError):
            verify_google_id_token(
                self.token(nonce=nonce), "another-client",
                hashlib.sha256(nonce.encode()).hexdigest()
            )


if __name__ == "__main__":
    unittest.main()
