import os
import uuid
import unittest
from urllib.parse import urlsplit, parse_qs
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.app import app, db, token_hash


class AccountEmailVerificationTests(unittest.TestCase):
    def setUp(self):
        with db() as connection:
            connection.execute("DELETE FROM security_rate_limits")

    def csrf(self, client):
        response = client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        return response.json()["csrf_token"]

    def register_unverified(self, client, email=None):
        email = email or ("verify-" + uuid.uuid4().hex + "@example.test")
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": self.csrf(client)},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertTrue(response.json()["email_verification_required"])
        url = response.json().get("development_verification_url")
        self.assertTrue(url, "Tests expect SMTP disabled and local verification URL enabled")
        token = parse_qs(urlsplit(url).query)["token"][0]
        return email, token

    def confirm(self, client, token):
        return client.post(
            "/api/auth/verify-email/confirm",
            json={"token": token},
            headers={"X-CSRF-Token": self.csrf(client)},
        )

    def test_registration_requires_email_verification_before_login(self):
        with patch.dict(os.environ, {
            "MCAS_EMAIL_SMTP_HOST": "",
            "MCAS_EMAIL_FROM": "",
            "MCAS_PUBLIC_BASE_URL": "http://localhost:8000",
        }), TestClient(app) as client:
            email, token = self.register_unverified(client)
            with db() as connection:
                row = connection.execute(
                    "SELECT email_verified FROM users WHERE email=?", (email,)
                ).fetchone()
                saved_token = connection.execute(
                    "SELECT token_hash FROM email_verification_tokens WHERE user_id=(SELECT id FROM users WHERE email=?)",
                    (email,),
                ).fetchone()
            self.assertEqual(row["email_verified"], 0)
            self.assertNotEqual(saved_token["token_hash"], token)
            login = client.post(
                "/api/auth/login",
                json={"email": email, "password": "UniqueStrongPassphrase!2026"},
                headers={"X-CSRF-Token": self.csrf(client)},
            )
            self.assertEqual(login.status_code, 403)
            self.assertIn("Verify your email", login.text)
            self.assertEqual(client.get("/api/leads").status_code, 401)

    def test_valid_token_is_single_use_and_allows_login(self):
        with patch.dict(os.environ, {
            "MCAS_EMAIL_SMTP_HOST": "",
            "MCAS_EMAIL_FROM": "",
            "MCAS_PUBLIC_BASE_URL": "http://localhost:8000",
        }), TestClient(app) as client:
            email, token = self.register_unverified(client)
            verified = self.confirm(client, token)
            self.assertEqual(verified.status_code, 200, verified.text)
            self.assertTrue(verified.json()["verified"])
            reused = self.confirm(client, token)
            self.assertEqual(reused.status_code, 400)
            login = client.post(
                "/api/auth/login",
                json={"email": email, "password": "UniqueStrongPassphrase!2026"},
                headers={"X-CSRF-Token": self.csrf(client)},
            )
            self.assertEqual(login.status_code, 200, login.text)
            self.assertEqual(client.get("/api/auth/me").status_code, 200)

    def test_expired_token_is_rejected(self):
        with patch.dict(os.environ, {
            "MCAS_EMAIL_SMTP_HOST": "",
            "MCAS_EMAIL_FROM": "",
            "MCAS_PUBLIC_BASE_URL": "http://localhost:8000",
        }), TestClient(app) as client:
            email, token = self.register_unverified(client)
            with db() as connection:
                connection.execute(
                    "UPDATE email_verification_tokens SET expires_at=0 WHERE user_id=(SELECT id FROM users WHERE email=?)",
                    (email,),
                )
            result = self.confirm(client, token)
            self.assertEqual(result.status_code, 400)

    def test_resend_replaces_old_token_and_unknown_email_response_is_generic(self):
        with patch.dict(os.environ, {
            "MCAS_EMAIL_SMTP_HOST": "",
            "MCAS_EMAIL_FROM": "",
            "MCAS_PUBLIC_BASE_URL": "http://localhost:8000",
        }), TestClient(app) as client:
            email, old_token = self.register_unverified(client)
            response = client.post(
                "/api/auth/resend-verification",
                json={"email": email},
                headers={"X-CSRF-Token": self.csrf(client)},
            )
            self.assertEqual(response.status_code, 200, response.text)
            new_token = parse_qs(urlsplit(response.json()["development_verification_url"]).query)["token"][0]
            self.assertNotEqual(old_token, new_token)
            self.assertEqual(self.confirm(client, old_token).status_code, 400)
            self.assertEqual(self.confirm(client, new_token).status_code, 200)

            unknown = client.post(
                "/api/auth/resend-verification",
                json={"email": "nobody-" + uuid.uuid4().hex + "@example.test"},
                headers={"X-CSRF-Token": self.csrf(client)},
            )
            self.assertEqual(unknown.status_code, 200)
            self.assertNotIn("development_verification_url", unknown.json())

    def test_verification_token_cannot_be_used_to_verify_another_account(self):
        with patch.dict(os.environ, {
            "MCAS_EMAIL_SMTP_HOST": "",
            "MCAS_EMAIL_FROM": "",
            "MCAS_PUBLIC_BASE_URL": "http://localhost:8000",
        }), TestClient(app) as client:
            email_a, token_a = self.register_unverified(client)
            email_b, _ = self.register_unverified(client)
            self.assertEqual(self.confirm(client, token_a).status_code, 200)
            with db() as connection:
                row_a = connection.execute("SELECT email_verified FROM users WHERE email=?", (email_a,)).fetchone()
                row_b = connection.execute("SELECT email_verified FROM users WHERE email=?", (email_b,)).fetchone()
            self.assertEqual(row_a["email_verified"], 1)
            self.assertEqual(row_b["email_verified"], 0)


if __name__ == "__main__":
    unittest.main()
