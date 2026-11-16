import os
import json
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

from backend.app import app, APP_VERSION, encrypt_mfa_secret


class UpdatesAndFeedbackTest(unittest.TestCase):
    def setUp(self):
        from backend.app import db
        with db() as connection:
            connection.execute("DELETE FROM security_rate_limits")
        self.mfa_key_patch = patch.dict(os.environ, {
            "MCAS_ADMIN_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode()
        })
        self.mfa_key_patch.start()
        self.addCleanup(self.mfa_key_patch.stop)

    def _register(self, client, email=None):
        email = email or ("updates-test-" + uuid.uuid4().hex + "@example.test")
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 201, response.text)
        from urllib.parse import urlsplit, parse_qs
        verification_url = response.json().get("development_verification_url")
        self.assertTrue(verification_url, response.text)
        raw_token = parse_qs(urlsplit(verification_url).query)["verify_token"][0]
        confirmed = client.post("/api/auth/verify-email/confirm", json={"token": raw_token},
            headers={"X-CSRF-Token": self._csrf(client)})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        login = client.post("/api/auth/login",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": self._csrf(client)})
        self.assertEqual(login.status_code, 200, login.text)
        return email

    def _csrf(self, client):
        return client.get("/api/auth/csrf").json()["csrf_token"]

    def _enable_admin_mfa(self, email):
        from backend.app import db
        test_secret = "JBSWY3DPEHPK3PXP"
        with db() as connection:
            connection.execute(
                "UPDATE users SET admin_totp_secret=? WHERE email=?",
                (encrypt_mfa_secret(test_secret), email),
            )
        return test_secret

    def test_updates_require_authentication_and_report_central_release(self):
        with TestClient(app) as anonymous:
            self.assertEqual(anonymous.get("/api/updates").status_code, 401)
        with TestClient(app) as client:
            self._register(client)
            result = client.get("/api/updates")
            self.assertEqual(result.status_code, 200, result.text)
            payload = result.json()
            self.assertEqual(payload["current_version"], APP_VERSION)
            self.assertEqual(payload["latest_version"], APP_VERSION)
            self.assertFalse(payload["update_available"])
            self.assertEqual(payload["delivery_model"], "centrally_managed")
            self.assertIn("operator", payload["message"].lower())

    def test_customer_feedback_is_private_to_submitting_account(self):
        with TestClient(app) as first, TestClient(app) as second:
            self._register(first)
            self._register(second)
            csrf = self._csrf(first)
            created = first.post(
                "/api/feedback",
                json={"category": "usability", "title": "Research flow confusing",
                      "message": "I cannot tell whether a prospect is verified or not."},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(created.status_code, 201, created.text)
            first_items = first.get("/api/feedback").json()
            second_items = second.get("/api/feedback").json()
            self.assertEqual(len(first_items), 1)
            self.assertEqual(second_items, [])
            self.assertEqual(first_items[0]["status"], "received")
            self.assertEqual(second.get("/api/admin/maintenance").status_code, 403)

    def test_feedback_requires_descriptive_content(self):
        with TestClient(app) as client:
            self._register(client)
            response = client.post(
                "/api/feedback",
                json={"category": "bug", "title": "No", "message": "Short"},
                headers={"X-CSRF-Token": self._csrf(client)},
            )
            self.assertEqual(response.status_code, 422)

    def test_configured_admin_can_review_feedback_and_customer_sees_status(self):
        customer_email = "customer-" + uuid.uuid4().hex + "@example.test"
        admin_email = "admin-" + uuid.uuid4().hex + "@example.test"
        with TestClient(app) as customer, TestClient(app) as admin:
            self._register(customer, customer_email)
            created = customer.post(
                "/api/feedback",
                json={"category": "feature", "title": "Keyboard shortcuts",
                      "message": "Please add keyboard shortcuts for common navigation tasks."},
                headers={"X-CSRF-Token": self._csrf(customer)},
            )
            self.assertEqual(created.status_code, 201, created.text)
            feedback_id = created.json()["id"]

            self._register(admin, admin_email)
            self.assertFalse(admin.get("/api/auth/me").json()["is_admin"])
            self.assertEqual(admin.get("/api/admin/maintenance").status_code, 403)

            with patch.dict(os.environ, {"MCAS_ADMIN_EMAILS": admin_email}):
                self._enable_admin_mfa(admin_email)
                self.assertTrue(admin.get("/api/auth/me").json()["is_admin"])
                dashboard = admin.get("/api/admin/maintenance")
                self.assertEqual(dashboard.status_code, 200, dashboard.text)
                self.assertGreaterEqual(dashboard.json()["feedback_total"], 1)
                matching = [item for item in dashboard.json()["feedback"] if item["id"] == feedback_id]
                self.assertEqual(len(matching), 1)
                self.assertEqual(matching[0]["customer_email"], customer_email)
                self.assertIn("not queried", dashboard.json()["workflow_status_source"].lower())

                reviewed = admin.patch(
                    "/api/admin/feedback/" + feedback_id,
                    json={"status": "planned", "admin_note": "Added to the product review backlog."},
                    headers={"X-CSRF-Token": self._csrf(admin)},
                )
                self.assertEqual(reviewed.status_code, 200, reviewed.text)

            customer_item = customer.get("/api/feedback").json()[0]
            self.assertEqual(customer_item["status"], "planned")
            self.assertEqual(customer_item["admin_note"], "Added to the product review backlog.")


    def test_ai_feedback_analysis_requires_explicit_consent_and_admin(self):
        customer_email = "optout-" + uuid.uuid4().hex + "@example.test"
        admin_email = "planner-" + uuid.uuid4().hex + "@example.test"
        with TestClient(app) as customer, TestClient(app) as non_admin:
            self._register(customer, customer_email)
            self._register(non_admin)
            created = customer.post(
                "/api/feedback",
                json={"category": "bug", "title": "Search button problem",
                      "message": "The search button does not respond after I click it."},
                headers={"X-CSRF-Token": self._csrf(customer)},
            )
            self.assertEqual(created.status_code, 201, created.text)
            self.assertEqual(
                non_admin.post("/api/admin/improvements/analyze",
                               headers={"X-CSRF-Token": self._csrf(non_admin)}).status_code,
                403,
            )
            with patch.dict(os.environ, {"MCAS_ADMIN_EMAILS": customer_email}):
                self._enable_admin_mfa(customer_email)
                sample = {
                    "summary": "Existing opted-in feedback can be reviewed.",
                    "recommendations": [{
                        "title": "Improve workflow clarity", "area": "Usability",
                        "problem": "Users need clearer workflow status.",
                        "suggested_change": "Show clear progress and completion states.",
                        "priority": "medium", "test_ideas": ["Check visible progress state."],
                    }],
                }
                with patch("backend.app.call_configured_ai", return_value=json.dumps(sample)) as ai_call:
                    result = customer.post(
                        "/api/admin/improvements/analyze",
                        headers={"X-CSRF-Token": self._csrf(customer)},
                    )
                    if result.status_code == 201:
                        sent = json.dumps(ai_call.call_args.args[0])
                        self.assertNotIn("Search button problem", sent)
                    else:
                        self.assertEqual(result.status_code, 409, result.text)
                        ai_call.assert_not_called()

    def test_ai_improvement_analysis_uses_only_opted_in_redacted_feedback(self):
        customer_email = "private-customer-" + uuid.uuid4().hex + "@example.test"
        admin_email = "improvement-admin-" + uuid.uuid4().hex + "@example.test"
        expected = {
            "summary": "Customers report a confusing search interaction and need clearer feedback.",
            "recommendations": [{
                "title": "Clarify search progress",
                "area": "Research workflow",
                "problem": "Users cannot tell whether a search is still running.",
                "suggested_change": "Show a visible progress state and a clear success or error result.",
                "priority": "medium",
                "test_ideas": ["Verify progress appears while a search is running."],
            }],
        }
        with TestClient(app) as customer, TestClient(app) as admin:
            self._register(customer, customer_email)
            opted_in = customer.post(
                "/api/feedback",
                json={
                    "category": "usability",
                    "title": "Search feedback",
                    "message": "Please contact me at tester@example.test. The research button gives no progress.",
                    "ai_analysis_consent": True,
                },
                headers={"X-CSRF-Token": self._csrf(customer)},
            )
            self.assertEqual(opted_in.status_code, 201, opted_in.text)
            not_opted_in = customer.post(
                "/api/feedback",
                json={
                    "category": "feature",
                    "title": "Private feature idea",
                    "message": "Please do not send this text to an AI provider.",
                },
                headers={"X-CSRF-Token": self._csrf(customer)},
            )
            self.assertEqual(not_opted_in.status_code, 201, not_opted_in.text)
            self._register(admin, admin_email)

            with patch.dict(os.environ, {"MCAS_ADMIN_EMAILS": admin_email}):
                self._enable_admin_mfa(admin_email)
                with patch("backend.app.call_configured_ai", return_value=json.dumps(expected)) as ai_call:
                    response = admin.post(
                        "/api/admin/improvements/analyze",
                        headers={"X-CSRF-Token": self._csrf(admin)},
                    )
                    self.assertEqual(response.status_code, 201, response.text)
                    self.assertEqual(response.json()["feedback_count"], 1)
                    sent_text = json.dumps(ai_call.call_args.args[0])
                    self.assertNotIn(customer_email, sent_text)
                    self.assertNotIn("tester@example.test", sent_text)
                    self.assertIn("[REDACTED EMAIL]", sent_text)
                    self.assertNotIn("Private feature idea", sent_text)
                    listing = admin.get("/api/admin/improvements")
                    self.assertEqual(listing.status_code, 200, listing.text)
                    saved = [item for item in listing.json() if item["id"] == response.json()["id"]]
                    self.assertEqual(len(saved), 1)
                    self.assertEqual(saved[0]["feedback_count"], 1)
                    repeated = admin.post(
                        "/api/admin/improvements/analyze",
                        headers={"X-CSRF-Token": self._csrf(admin)},
                    )
                    self.assertEqual(repeated.status_code, 409, repeated.text)

    def test_invalid_ai_improvement_response_is_not_saved(self):
        customer_email = "invalid-ai-" + uuid.uuid4().hex + "@example.test"
        admin_email = "invalid-ai-admin-" + uuid.uuid4().hex + "@example.test"
        with TestClient(app) as customer, TestClient(app) as admin:
            self._register(customer, customer_email)
            customer.post(
                "/api/feedback",
                json={"category": "bug", "title": "Search crashes",
                      "message": "Search crashes when I press the run button.",
                      "ai_analysis_consent": True},
                headers={"X-CSRF-Token": self._csrf(customer)},
            )
            self._register(admin, admin_email)
            with patch.dict(os.environ, {"MCAS_ADMIN_EMAILS": admin_email}):
                self._enable_admin_mfa(admin_email)
                before_ids = {item["id"] for item in admin.get("/api/admin/improvements").json()}
                with patch("backend.app.call_configured_ai", return_value="not-json"):
                    response = admin.post(
                        "/api/admin/improvements/analyze",
                        headers={"X-CSRF-Token": self._csrf(admin)},
                    )
                    self.assertEqual(response.status_code, 502, response.text)
                after_ids = {item["id"] for item in admin.get("/api/admin/improvements").json()}
                self.assertEqual(after_ids, before_ids)

    def test_onboarding_requires_authentication(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/onboarding").status_code, 401)

    def test_onboarding_progress_is_workspace_specific(self):
        with TestClient(app) as first, TestClient(app) as second:
            self._register(first)
            self._register(second)

            initial = first.get("/api/onboarding")
            self.assertEqual(initial.status_code, 200, initial.text)
            self.assertEqual(initial.json()["completed"], 0)
            self.assertEqual(initial.json()["percent"], 0)

            created = first.post(
                "/api/leads",
                json={"name": "Onboarding Sample Prospect", "market": "Nairobi"},
                headers={"X-CSRF-Token": self._csrf(first)},
            )
            self.assertEqual(created.status_code, 201, created.text)

            updated = first.get("/api/onboarding").json()
            other = second.get("/api/onboarding").json()
            self.assertEqual(updated["completed"], 1)
            self.assertEqual(updated["steps"][0]["id"], "prospect")
            self.assertTrue(updated["steps"][0]["completed"])
            self.assertEqual(other["completed"], 0)
            self.assertEqual(other["percent"], 0)
            self.assertTrue(updated["optional_steps"][0]["optional"])

    def test_non_admin_cannot_change_feedback_status(self):
        with TestClient(app) as client:
            self._register(client)
            csrf = self._csrf(client)
            created = client.post(
                "/api/feedback",
                json={"category": "bug", "title": "Broken action",
                      "message": "The save button did not respond when clicked."},
                headers={"X-CSRF-Token": csrf},
            )
            feedback_id = created.json()["id"]
            response = client.patch(
                "/api/admin/feedback/" + feedback_id,
                json={"status": "completed", "admin_note": ""},
                headers={"X-CSRF-Token": self._csrf(client)},
            )
            self.assertEqual(response.status_code, 403)


    def test_improvement_decisions_require_admin_and_follow_review_gates(self):
        from backend.app import db, now
        customer_email = "improvement-customer-" + uuid.uuid4().hex + "@example.test"
        admin_email = "improvement-admin-" + uuid.uuid4().hex + "@example.test"
        with TestClient(app) as customer, TestClient(app) as admin:
            self._register(customer, customer_email)
            self._register(admin, admin_email)
            with patch.dict(os.environ, {"MCAS_ADMIN_EMAILS": admin_email}):
                self._enable_admin_mfa(admin_email)
                admin_user = admin.get("/api/auth/me").json()
                review_id = "review-" + uuid.uuid4().hex
                recommendation = [{
                    "title": "Improve dashboard clarity",
                    "area": "Usability",
                    "problem": "Customers report unclear dashboard status.",
                    "suggested_change": "Show explicit progress and completion states.",
                    "priority": "medium",
                    "test_ideas": ["Verify status transitions on desktop and mobile."]
                }]
                with db() as connection:
                    connection.execute(
                        """INSERT INTO improvement_reviews
                           (id,created_by,summary,recommendations_json,feedback_count,created_at)
                           VALUES(?,?,?,?,?,?)""",
                        (review_id, admin_user["id"], "A usability improvement proposal.",
                         json.dumps(recommendation), 2, now()),
                    )

                endpoint = "/api/admin/improvements/" + review_id + "/0"
                self.assertEqual(customer.get("/api/admin/improvements").status_code, 403)
                self.assertEqual(customer.patch(endpoint, json={
                    "status": "approved_for_development"
                }, headers={"X-CSRF-Token": self._csrf(customer)}).status_code, 403)

                listed = admin.get("/api/admin/improvements")
                self.assertEqual(listed.status_code, 200, listed.text)
                self.assertEqual(listed.json()[0]["recommendations"][0]["decision"]["status"], "pending_review")

                def save(status, **extra):
                    payload = {"status": status, **extra}
                    return admin.patch(endpoint, json=payload,
                        headers={"X-CSRF-Token": self._csrf(admin)})

                self.assertEqual(save("approved_for_release").status_code, 409)
                self.assertEqual(save("approved_for_development").status_code, 200)
                self.assertEqual(save("in_development", code_branch="feature/dashboard-status").status_code, 200)
                base = {
                    "code_branch": "feature/dashboard-status",
                    "pull_request_url": "https://github.com/example/mcas/pull/12",
                    "test_evidence": "Unit tests passed; JavaScript syntax passed; CodeQL passed.",
                    "evidence_justification": "Three opted-in reports describe the same dashboard progress confusion.",
                    "risk_assessment": "Low risk UI-only change; verify privacy, accessibility and regression behavior.",
                }
                self.assertEqual(save("testing", **base,
                    test_environment_url="http://127.0.0.1:8000",
                    test_environment_status="prepared").status_code, 200)
                release = {**base, "test_environment_url": "https://staging.example.test",
                           "test_environment_status": "passed"}
                self.assertEqual(save("ready_for_release", **release).status_code, 200)
                self.assertEqual(save("approved_for_release", **release).status_code, 200)
                self.assertEqual(save("implemented", **release).status_code, 200)
                rollback = admin.post(endpoint + "/rollback", json={
                    "reason": "The new dashboard progress panel caused a confirmed regression.",
                    "recovery_reference": "release-1.4.0-revert",
                    "verification_notes": "Restored version passed smoke tests."
                }, headers={"X-CSRF-Token": self._csrf(admin)})
                self.assertEqual(rollback.status_code, 200, rollback.text)
                self.assertEqual(rollback.json()["status"], "rolled_back")
                final = admin.get("/api/admin/improvements").json()[0]["recommendations"][0]["decision"]
                self.assertEqual(final["status"], "rolled_back")
                self.assertGreaterEqual(len(final["history"]), 6)


if __name__ == "__main__":
    unittest.main()
