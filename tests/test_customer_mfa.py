import hashlib
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import backend.app as mcas


class CustomerMfaTests(unittest.TestCase):
    def setUp(self):
        self.original_db_path = mcas.DB_PATH
        self.tempdir = tempfile.TemporaryDirectory(prefix="mcas-customer-mfa-")
        mcas.DB_PATH = Path(self.tempdir.name) / "mcas-test.sqlite3"
        mcas.init_db()
        self.email = "customer-" + uuid.uuid4().hex + "@example.test"
        self.subject = "google-customer-" + uuid.uuid4().hex
        self.customer_key = Fernet.generate_key().decode()
        self.env = patch.dict(os.environ, {
            "GOOGLE_CLIENT_ID": "test-google-client-id",
            "MCAS_CUSTOMER_MFA_ENCRYPTION_KEY": self.customer_key,
            "MCAS_ADMIN_EMAILS": "other-admin@example.test",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.prod = patch.object(mcas, "IS_PROD", True)
        self.prod.start()
        self.addCleanup(self.prod.stop)
        self.customer_required = patch.object(mcas, "CUSTOMER_MFA_REQUIRED", True)
        self.customer_required.start()
        self.addCleanup(self.customer_required.stop)
        self.admin_required = patch.object(mcas, "ADMIN_MFA_REQUIRED", True)
        self.admin_required.start()
        self.addCleanup(self.admin_required.stop)

    def tearDown(self):
        mcas.DB_PATH = self.original_db_path
        self.tempdir.cleanup()

    def google_login(self, client):
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        nonce_response = client.get("/api/auth/google/nonce")
        self.assertEqual(nonce_response.status_code, 200, nonce_response.text)
        nonce = nonce_response.json()["nonce"]
        with patch.object(mcas, "verify_google_id_token", return_value={
            "email": self.email, "sub": self.subject, "name": "MCAS customer"
        }):
            result = client.post(
                "/api/auth/google",
                json={"credential": "x" * 60, "nonce": nonce},
                headers={"Origin": "http://localhost:8000", "X-CSRF-Token": csrf},
            )
        self.assertEqual(result.status_code, 200, result.text)
        return result

    def test_new_customer_has_limited_session_until_mfa_enrollment(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            login = self.google_login(client)
            self.assertTrue(login.json()["customer_mfa_setup_required"])
            self.assertFalse(login.json()["is_admin"])
            self.assertEqual(client.get("/api/customer/mfa/status").status_code, 200)
            self.assertEqual(client.get("/api/auth/me").status_code, 403)
            self.assertEqual(client.get("/api/leads").status_code, 403)
            self.assertEqual(client.get("/api/billing/status").status_code, 403)

    def test_customer_enrolment_rotates_session_and_unlocks_workspace(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            self.google_login(client)
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            started = client.post(
                "/api/customer/mfa/setup", json={},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(started.status_code, 200, started.text)
            secret = started.json()["secret"]
            self.assertIn("otpauth://totp/", started.json()["otpauth_uri"])
            code = mcas.totp_code(secret)
            verified = client.post(
                "/api/customer/mfa/verify", json={"code": code},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(verified.status_code, 200, verified.text)
            self.assertEqual(len(verified.json()["recovery_codes"]), 10)
            self.assertTrue(verified.json()["enabled"])
            profile = client.get("/api/auth/me")
            self.assertEqual(profile.status_code, 200, profile.text)
            self.assertFalse(profile.json()["is_admin"])
            self.assertEqual(client.get("/api/leads").status_code, 200)

    def test_existing_customer_mfa_login_requires_authenticator_or_unused_recovery_code(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            self.google_login(client)
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            started = client.post(
                "/api/customer/mfa/setup", json={},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(started.status_code, 200, started.text)
            secret = started.json()["secret"]
            enabled = client.post(
                "/api/customer/mfa/verify",
                json={"code": mcas.totp_code(secret)},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(enabled.status_code, 200, enabled.text)
            recovery = enabled.json()["recovery_codes"][0]

            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
            second_login = self.google_login(client)
            self.assertTrue(second_login.json()["mfa_required"])
            self.assertEqual(second_login.json()["mfa_type"], "customer")
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            completed = client.post(
                "/api/auth/mfa", json={"code": recovery},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(completed.status_code, 200, completed.text)
            self.assertTrue(completed.json()["mfa_verified"])
            self.assertEqual(completed.json()["mfa_type"], "customer")
            self.assertEqual(client.get("/api/leads").status_code, 200)

            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
            third_login = self.google_login(client)
            self.assertTrue(third_login.json()["mfa_required"])
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            replayed = client.post(
                "/api/auth/mfa", json={"code": recovery},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(replayed.status_code, 401)

    def test_invalid_enrollment_code_is_rejected_and_attempts_are_recorded(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            self.google_login(client)
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            started = client.post(
                "/api/customer/mfa/setup", json={},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(started.status_code, 200)
            with patch.object(mcas, "totp_counter_for_code", return_value=None):
                invalid = client.post(
                    "/api/customer/mfa/verify", json={"code": "123456"},
                    headers={"X-CSRF-Token": csrf},
                )
            self.assertEqual(invalid.status_code, 422)
            status = client.get("/api/customer/mfa/status")
            self.assertEqual(status.status_code, 200)
            self.assertTrue(status.json()["setup_pending"])

    def test_customer_setup_routes_reject_admin_and_unauthenticated_requests(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            self.assertEqual(client.get("/api/customer/mfa/status").status_code, 401)
            email = self.email
            user_id = "admin-" + uuid.uuid4().hex
            with mcas.db() as connection:
                connection.execute(
                    "INSERT INTO users(id,email,password_hash,created_at,google_subject) VALUES(?,?,?,?,?)",
                    (user_id, "other-admin@example.test", mcas.password_hash("Strong password 2026!"),
                     mcas.now(), "verified-admin-subject"),
                )
                session = "admin-session-" + uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                    (mcas.token_hash(session), user_id, int(mcas.time.time()) + mcas.SESSION_SECONDS),
                )
            client.cookies.set(mcas.COOKIE, session)
            denied = client.get("/api/customer/mfa/status")
            self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
