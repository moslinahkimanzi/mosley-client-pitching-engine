import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app as mcas


class CompetitorIntelligenceTest(unittest.TestCase):
    def setUp(self):
        with mcas.db() as connection:
            connection.execute("DELETE FROM security_rate_limits")

    def _client(self):
        client = TestClient(mcas.app)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        email = "competitor-test-" + uuid.uuid4().hex + "@example.test"
        registered = client.post(
            "/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(registered.status_code, 201, registered.text)
        return client, client.get("/api/auth/csrf").json()["csrf_token"]

    def test_competitor_research_is_tenant_scoped_and_labels_candidates(self):
        client, csrf = self._client()
        created = client.post(
            "/api/leads",
            json={
                "name": "Target Test Restaurant",
                "market": "Nairobi",
                "website": "https://target.example",
                "status": "Unverified",
                "evidence": "Test fixture only.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(created.status_code, 201, created.text)
        lead_id = created.json()["id"]
        places = {
            "places": [
                {
                    "title": "Neighbourhood Cafe",
                    "category": "Cafe",
                    "address": "2 Example Road, Nairobi",
                    "website": "https://cafe.example",
                    "rating": 4.4,
                    "ratingCount": 18,
                    "cid": "12345",
                },
                {
                    "title": "Local Bistro",
                    "category": "Restaurant",
                    "address": "3 Example Road, Nairobi",
                    "rating": 4.1,
                    "ratingCount": 9,
                },
            ]
        }
        fake_audit = {
            "http_status": 200,
            "pages_checked": 2,
            "summary": {"health_score": 92, "total": 1, "high": 0, "medium": 0, "low": 1},
        }
        with patch.object(mcas, "serper_request", return_value=places) as search, patch.object(
            mcas, "advanced_site_audit", return_value=fake_audit
        ) as site_audit:
            response = client.post(
                "/api/competitor-intelligence",
                json={"lead_id": lead_id, "industry": "restaurant", "max_results": 5},
                headers={"X-CSRF-Token": csrf},
            )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["comparison"]["competitors_found"], 2)
        self.assertEqual(data["comparison"]["with_listed_websites"], 1)
        self.assertEqual(data["competitors"][0]["website_state"], "responding")
        self.assertEqual(data["competitors"][0]["audit_summary"]["health_score"], 92)
        self.assertEqual(data["competitors"][1]["website_state"], "not_listed")
        self.assertIn("candidate competitors", " ".join(data["limitations"]))
        search.assert_called_once()
        self.assertEqual(search.call_args.args[0], "places")
        self.assertIn("Nairobi", search.call_args.args[1]["q"])
        site_audit.assert_called_once_with("https://cafe.example", mcas.safe_site_fetch, 3)

        # Intelligence is read-only: it must not create proposals or outreach drafts.
        self.assertEqual(client.get("/api/proposals").json(), [])
        self.assertEqual(client.get("/api/drafts").json(), [])

    def test_competitor_research_rejects_another_tenant_prospect(self):
        client, csrf = self._client()
        response = client.post(
            "/api/competitor-intelligence",
            json={"lead_id": "not-owned-by-this-account", "industry": "restaurant", "max_results": 5},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
