import base64
import json
import os
import secrets
import unittest
import uuid
from unittest.mock import patch
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet
from backend.app import app, db, encrypt_mfa_secret, totp_code

# Generate disposable test credentials at runtime; do not commit fixed secrets.
PASSWORD = secrets.token_urlsafe(32) + "!A1"
BOOTSTRAP = secrets.token_urlsafe(48)
TOTP_SECRET = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
AI_RESULT = {
    "summary": "Feedback points to unclear research status and a need for progress information.",
    "recommendations": [{
        "title": "Show research progress", "area": "Research",
        "problem": "Users cannot tell when research is running.",
        "suggested_change": "Show a progress indicator and a final result state.",
        "priority": "medium",
        "test_ideas": ["Verify that progress is visible during a research run."],
    }],
}


class AdminSecurityTest(unittest.TestCase):
    def setUp(self):
        # Rate limits are keyed by IP and shared across TestClient instances.
        # Clear them between tests so one test cannot throttle another.
        with db() as connection:
            connection.execute("DELETE FROM security_rate_limits")
        self.mfa_key_patch = patch.dict(os.environ, {
            "MCAS_ADMIN_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode()
        })
        self.mfa_key_patch.start()
        self.addCleanup(self.mfa_key_patch.stop)

    def csrf(self, client):
        return client.get("/api/auth/csrf").json()["csrf_token"]

    def register(self, client, email, token=""):
        return client.post(
            "/api/auth/register",
            json={"email": email, "password": PASSWORD, "admin_bootstrap_token": token},
            headers={"X-CSRF-Token": self.csrf(client)},
        )

    def enable_test_mfa(self, email):
        with db() as c:
            c.execute("UPDATE users SET admin_totp_secret=? WHERE email=?",
                      (encrypt_mfa_secret(TOTP_SECRET), email))

    def test_configured_admin_registration_requires_bootstrap_token(self):
        email = "bootstrap-" + uuid.uuid4().hex + "@example.test"
        with TestClient(app) as client, patch.dict(os.environ, {
            "MCAS_ADMIN_EMAILS": email, "MCAS_ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP
        }):
            denied = self.register(client, email, "wrong-but-long-enough-bootstrap-token")
            self.assertEqual(denied.status_code, 403)
            accepted = self.register(client, email, BOOTSTRAP)
            self.assertEqual(accepted.status_code, 201, accepted.text)

    def test_admin_mfa_setup_revokes_session_and_login_requires_totp(self):
        email = "mfa-admin-" + uuid.uuid4().hex + "@example.test"
        with TestClient(app) as client, patch.dict(os.environ, {
            "MCAS_ADMIN_EMAILS": email, "MCAS_ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP
        }):
            self.assertEqual(self.register(client, email, BOOTSTRAP).status_code, 201)
            self.assertEqual(client.get("/api/admin/maintenance").status_code, 403)
            setup = client.post("/api/admin/mfa/setup",
                json={"password": PASSWORD, "bootstrap_token": BOOTSTRAP},
                headers={"X-CSRF-Token": self.csrf(client)})
            self.assertEqual(setup.status_code, 200, setup.text)
            secret = setup.json()["secret"]
            with db() as c:
                stored = c.execute("SELECT admin_totp_pending_secret FROM users WHERE email=?", (email,)).fetchone()[0]
            self.assertNotEqual(stored, secret)
            enabled = client.post("/api/admin/mfa/verify", json={"code": totp_code(secret)},
                headers={"X-CSRF-Token": self.csrf(client)})
            self.assertEqual(enabled.status_code, 200, enabled.text)
            self.assertEqual(client.get("/api/auth/me").status_code, 401)
            login = client.post("/api/auth/login", json={"email": email, "password": PASSWORD},
                headers={"X-CSRF-Token": self.csrf(client)})
            self.assertTrue(login.json()["mfa_required"])
            valid = client.post("/api/auth/mfa", json={"code": totp_code(secret)},
                headers={"X-CSRF-Token": self.csrf(client)})
            self.assertEqual(valid.status_code, 200, valid.text)
            self.assertTrue(client.get("/api/auth/me").json()["is_admin"])
            self.assertEqual(client.get("/api/admin/maintenance").status_code, 200)

            # A correct password alone must not revoke the current session.
            second_password_step = client.post(
                "/api/auth/login",
                json={"email": email, "password": PASSWORD},
                headers={"X-CSRF-Token": self.csrf(client)},
            )
            self.assertTrue(second_password_step.json()["mfa_required"])
            self.assertEqual(client.get("/api/auth/me").status_code, 200)
            second_factor = client.post(
                "/api/auth/mfa",
                json={"code": totp_code(secret)},
                headers={"X-CSRF-Token": self.csrf(client)},
            )
            self.assertEqual(second_factor.status_code, 200, second_factor.text)

    def test_invalid_mfa_codes_are_limited_to_five_per_challenge(self):
        email = "mfa-lock-" + uuid.uuid4().hex + "@example.test"
        with TestClient(app) as client, patch.dict(os.environ, {
            "MCAS_ADMIN_EMAILS": email, "MCAS_ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP
        }):
            self.assertEqual(self.register(client, email, BOOTSTRAP).status_code, 201)
            setup = client.post("/api/admin/mfa/setup",
                json={"password": PASSWORD, "bootstrap_token": BOOTSTRAP},
                headers={"X-CSRF-Token": self.csrf(client)})
            secret = setup.json()["secret"]
            self.assertEqual(client.post("/api/admin/mfa/verify", json={"code": totp_code(secret)},
                headers={"X-CSRF-Token": self.csrf(client)}).status_code, 200)
            login = client.post("/api/auth/login", json={"email": email, "password": PASSWORD},
                headers={"X-CSRF-Token": self.csrf(client)})
            self.assertTrue(login.json()["mfa_required"])
            wrong = "000000" if totp_code(secret) != "000000" else "000001"
            for _ in range(5):
                result = client.post("/api/auth/mfa", json={"code": wrong},
                    headers={"X-CSRF-Token": self.csrf(client)})
                self.assertEqual(result.status_code, 401)
            self.assertEqual(client.get("/api/auth/me").status_code, 401)

    def test_customer_can_withdraw_only_their_own_ai_consent(self):
        with TestClient(app) as owner, TestClient(app) as other:
            owner_email = "consent-owner-" + uuid.uuid4().hex + "@example.test"
            other_email = "consent-other-" + uuid.uuid4().hex + "@example.test"
            self.assertEqual(self.register(owner, owner_email).status_code, 201)
            self.assertEqual(self.register(other, other_email).status_code, 201)
            made = owner.post("/api/feedback", json={
                "category": "usability", "title": "Progress display",
                "message": "Show a clear status while research is running.",
                "ai_analysis_consent": True,
            }, headers={"X-CSRF-Token": self.csrf(owner)})
            self.assertEqual(made.status_code, 201, made.text)
            fid = made.json()["id"]
            denied = other.delete("/api/feedback/" + fid + "/ai-consent",
                headers={"X-CSRF-Token": self.csrf(other)})
            self.assertEqual(denied.status_code, 404)
            withdrawn = owner.delete("/api/feedback/" + fid + "/ai-consent",
                headers={"X-CSRF-Token": self.csrf(owner)})
            self.assertEqual(withdrawn.status_code, 200, withdrawn.text)
            saved = next(x for x in owner.get("/api/feedback").json() if x["id"] == fid)
            self.assertEqual(saved["ai_analysis_consent"], 0)

    def test_monthly_ai_analysis_quota_is_enforced(self):
        admin_email = "quota-admin-" + uuid.uuid4().hex + "@example.test"
        with db() as connection:
            connection.execute("DELETE FROM ai_analysis_usage WHERE month='2099-01'")
        with TestClient(app) as customer, TestClient(app) as admin:
            self.assertEqual(self.register(customer, "quota-user-" + uuid.uuid4().hex + "@example.test").status_code, 201)
            for title, msg in [
                ("First feedback", "Research needs a clear progress indicator."),
                ("Second feedback", "Show users when the research has finished."),
            ]:
                created = customer.post("/api/feedback", json={
                    "category": "usability", "title": title, "message": msg, "ai_analysis_consent": True,
                }, headers={"X-CSRF-Token": self.csrf(customer)})
                self.assertEqual(created.status_code, 201, created.text)
            self.assertEqual(self.register(admin, admin_email).status_code, 201)
            self.enable_test_mfa(admin_email)
            with patch.dict(os.environ, {
                "MCAS_ADMIN_EMAILS": admin_email, "MCAS_AI_IMPROVEMENT_MONTHLY_LIMIT": "1"
            }), patch("backend.app.utc_month", return_value="2099-01"):
                with patch("backend.app.call_configured_ai", return_value=json.dumps(AI_RESULT)) as ai:
                    first = admin.post("/api/admin/improvements/analyze",
                        headers={"X-CSRF-Token": self.csrf(admin)})
                    self.assertEqual(first.status_code, 201, first.text)
                    self.assertEqual(first.json()["monthly_analysis_limit"], 1)
                    extra = customer.post("/api/feedback", json={
                        "category": "usability", "title": "Third feedback",
                        "message": "Research should show a clear completion notice.",
                        "ai_analysis_consent": True,
                    }, headers={"X-CSRF-Token": self.csrf(customer)})
                    self.assertEqual(extra.status_code, 201, extra.text)
                    second = admin.post("/api/admin/improvements/analyze",
                        headers={"X-CSRF-Token": self.csrf(admin)})
                    self.assertEqual(second.status_code, 429, second.text)
                    self.assertEqual(ai.call_count, 1)


if __name__ == "__main__":
    unittest.main()
