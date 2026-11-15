import os
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import app, APP_VERSION


class UpdatesAndFeedbackTest(unittest.TestCase):
    def setUp(self):
        from backend.app import db
        with db() as connection:
            connection.execute("DELETE FROM security_rate_limits")

    def _register(self, client, email=None):
        email = email or ("updates-test-" + uuid.uuid4().hex + "@example.test")
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return email

    def _csrf(self, client):
        return client.get("/api/auth/csrf").json()["csrf_token"]

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


if __name__ == "__main__":
    unittest.main()
