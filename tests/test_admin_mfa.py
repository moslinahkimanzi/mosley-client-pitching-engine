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


class AdminMfaTests(unittest.TestCase):
    def setUp(self):
        self.original_db_path = mcas.DB_PATH
        self.tempdir = tempfile.TemporaryDirectory(prefix="mcas-admin-mfa-")
        mcas.DB_PATH = Path(self.tempdir.name) / "mcas-test.sqlite3"
        mcas.init_db()
        self.email = "admin-" + uuid.uuid4().hex + "@example.test"
        self.subject = "google-subject-" + uuid.uuid4().hex
        self.bootstrap = "bootstrap-" + uuid.uuid4().hex + "-one-time-token"
        self.encryption_key = Fernet.generate_key().decode()
        self.env = patch.dict(os.environ, {
            "MCAS_ADMIN_EMAILS": self.email,
            "MCAS_ADMIN_BOOTSTRAP_TOKEN": self.bootstrap,
            "MCAS_ADMIN_MFA_ENCRYPTION_KEY": self.encryption_key,
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.prod = patch.object(mcas, "IS_PROD", True)
        self.prod.start()
        self.addCleanup(self.prod.stop)
        self.required = patch.object(mcas, "ADMIN_MFA_REQUIRED", True)
        self.required.start()
        self.addCleanup(self.required.stop)

    def tearDown(self):
        mcas.DB_PATH = self.original_db_path
        self.tempdir.cleanup()

    def make_admin(self, client, enabled_secret=None):
        user_id = "mfa-user-" + uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO users(id,email,password_hash,created_at,google_subject,admin_totp_secret)
                   VALUES(?,?,?,?,?,?)""",
                (user_id, self.email, mcas.password_hash("Strong test password 2026!"),
                 mcas.now(), self.subject, enabled_secret),
            )
            session = "test-session-" + uuid.uuid4().hex
            connection.execute(
                "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                (mcas.token_hash(session), user_id, int(mcas.time.time()) + mcas.SESSION_SECONDS),
            )
        client.cookies.set(mcas.COOKIE, session)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        return user_id, csrf

    def sign_in_through_google(self, client):
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        nonce = client.get("/api/auth/google/nonce").json()["nonce"]
        with patch.object(mcas, "verify_google_id_token", return_value={
            "email": self.email, "sub": self.subject, "name": "MCAS admin"
        }):
            response = client.post(
                "/api/auth/google",
                json={"credential": "x" * 60, "nonce": nonce},
                headers={"Origin": "http://localhost:8000", "X-CSRF-Token": csrf},
            )
        return response, csrf

    def test_totp_generates_and_checks_six_digit_codes(self):
        secret = mcas.generate_totp_secret()
        timestamp = 1_800_000_000
        code = mcas.totp_code(secret, timestamp)
        self.assertRegex(code, r"^\d{6}$")
        self.assertEqual(mcas.totp_counter_for_code(secret, code, timestamp), int(timestamp // 30))
        self.assertIsNone(mcas.totp_counter_for_code(secret, "bad-code", timestamp))

    def test_production_admin_tools_and_unlimited_credits_require_enrolled_mfa(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            user_id, _ = self.make_admin(client)
            status = client.get("/api/billing/status")
            self.assertEqual(status.status_code, 200, status.text)
            self.assertFalse(status.json()["is_unlimited_admin"])
            with self.assertRaises(Exception):
                mcas.require_admin({"id": user_id, "email": self.email, "google_subject": self.subject})

            secret = mcas.generate_totp_secret()
            with mcas.db() as connection:
                connection.execute(
                    "UPDATE users SET admin_totp_secret=? WHERE id=?",
                    (mcas.encrypt_mfa_secret(secret), user_id),
                )
            status = client.get("/api/billing/status")
            self.assertTrue(status.json()["is_unlimited_admin"])
            mcas.require_credits(user_id, 1_000_000)
            mcas.debit_credits(user_id, 1_000_000, "mfa_test")
            with mcas.db() as connection:
                audit_row = connection.execute(
                    "SELECT 1 FROM audit_log WHERE user_id=? AND action='billing.admin_unlimited_usage'",
                    (user_id,),
                ).fetchone()
            self.assertIsNotNone(audit_row)

    def test_admin_can_enrol_mfa_and_receives_ten_recovery_codes_once(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            user_id, csrf = self.make_admin(client)
            status = client.get("/api/admin/mfa/status")
            self.assertEqual(status.status_code, 200, status.text)
            self.assertFalse(status.json()["enabled"])

            started = client.post(
                "/api/admin/mfa/setup",
                json={"bootstrap_token": self.bootstrap},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(started.status_code, 200, started.text)
            secret = started.json()["secret"]
            self.assertIn("otpauth://totp/", started.json()["otpauth_uri"])

            code = mcas.totp_code(secret)
            verified = client.post(
                "/api/admin/mfa/verify",
                json={"code": code},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(verified.status_code, 200, verified.text)
            self.assertTrue(verified.json()["enabled"])
            self.assertEqual(len(verified.json()["recovery_codes"]), 10)
            self.assertEqual(len(set(verified.json()["recovery_codes"])), 10)
            with mcas.db() as connection:
                row = connection.execute(
                    "SELECT admin_totp_secret,admin_totp_pending_secret FROM users WHERE id=?",
                    (user_id,),
                ).fetchone()
            self.assertTrue(row["admin_totp_secret"])
            self.assertIsNone(row["admin_totp_pending_secret"])
            self.assertEqual(client.get("/api/admin/mfa/status").status_code, 401)

    def test_google_admin_signin_requires_mfa_and_recovery_code_is_single_use(self):
        secret = mcas.generate_totp_secret()
        recovery = "one-time-" + uuid.uuid4().hex[:18]
        encrypted = mcas.encrypt_mfa_secret(secret)
        with TestClient(mcas.app, base_url="https://testserver") as client:
            user_id, _ = self.make_admin(client, encrypted)
            with mcas.db() as connection:
                connection.execute(
                    "INSERT INTO admin_mfa_recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)",
                    (user_id, hashlib.sha256(recovery.encode()).hexdigest(), mcas.now()),
                )
            first, _ = self.sign_in_through_google(client)
            self.assertEqual(first.status_code, 200, first.text)
            self.assertTrue(first.json()["mfa_required"])
            self.assertIsNotNone(client.cookies.get("mcas_mfa_challenge"))

            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            completed = client.post(
                "/api/auth/mfa",
                json={"code": recovery},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(completed.status_code, 200, completed.text)
            self.assertTrue(completed.json()["mfa_verified"])
            self.assertEqual(client.get("/api/admin/mfa/status").status_code, 200)

            logout_csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            client.post("/api/auth/logout", headers={"X-CSRF-Token": logout_csrf})
            second, _ = self.sign_in_through_google(client)
            self.assertTrue(second.json()["mfa_required"])
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            replayed = client.post(
                "/api/auth/mfa",
                json={"code": recovery},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(replayed.status_code, 401)

    def test_invalid_bootstrap_token_does_not_start_enrollment(self):
        with TestClient(mcas.app, base_url="https://testserver") as client:
            self.make_admin(client)
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            response = client.post(
                "/api/admin/mfa/setup",
                json={"bootstrap_token": "wrong-bootstrap-token-value-that-is-long-enough"},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
