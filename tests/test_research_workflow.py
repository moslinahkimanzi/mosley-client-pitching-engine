import time
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app as mcas


class ResearchWorkflowTest(unittest.TestCase):
    def setUp(self):
        mcas._rate_windows.clear()

    def _registered_client(self):
        client = TestClient(mcas.app)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        email = "research-test-" + uuid.uuid4().hex + "@example.test"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 201, response.text)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        return client, csrf

    def test_manual_research_saves_prospect_proposal_and_pending_email(self):
        client, csrf = self._registered_client()
        elements = [
            {
                "type": "node",
                "id": 12345,
                "tags": {
                    "name": "Research Test Italian Restaurant",
                    "amenity": "restaurant",
                    "cuisine": "italian",
                },
            }
        ]
        with patch.object(mcas, "geocode_location", return_value={"display_name": "Nairobi, Kenya", "bbox": (-1.45, 36.65, -1.15, 37.05), "place_type": "city"}), patch.dict(mcas._OVERPASS_CACHE, {
            "nairobi|restaurant": (time.time(), elements)
        }):
            response = client.post(
                "/api/research/run",
                json={
                    "location": "Nairobi",
                    "industry": "restaurant",
                    "keywords": "italian",
                    "max_results": 6,
                },
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["saved"], 1)
        self.assertEqual(result["results"][0]["website_state"], "not_listed")
        self.assertEqual(result["resolved_location"], "Nairobi, Kenya")
        self.assertGreaterEqual(result["results"][0]["opportunity_score"], 0)
        self.assertIn("highest_opportunity_score", result["summary"])
        self.assertTrue(result["results"][0]["proposal_created"])
        self.assertTrue(result["results"][0]["draft_created"])
        self.assertFalse(result["results"][0]["gmail_draft_created"])

        self.assertEqual(len(client.get("/api/leads").json()), 1)
        self.assertEqual(len(client.get("/api/proposals").json()), 1)
        drafts = client.get("/api/drafts").json()
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0]["state"], "pending_approval")
        self.assertIn("does not necessarily mean", drafts[0]["body"].lower())

    def test_builder_prompt_requires_client_acceptance_and_uses_business_category(self):
        client, csrf = self._registered_client()
        lead = client.post(
            "/api/leads",
            json={
                "name": "Prompt Restaurant",
                "market": "Nairobi",
                "evidence": "OpenStreetMap category amenity: restaurant.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(lead.status_code, 201, lead.text)
        lead_id = lead.json()["id"]

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        rejected = client.post(
            f"/api/leads/{lead_id}/builder-prompt",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(rejected.status_code, 409)

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        accepted = client.patch(
            f"/api/leads/{lead_id}",
            json={
                "name": "Prompt Restaurant",
                "website": None,
                "market": "Nairobi",
                "evidence": "OpenStreetMap category amenity: restaurant.",
                "status": "Won",
                "contact_email": None,
                "contact_phone": None,
                "source_url": None,
                "do_not_contact": False,
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        generated = client.post(
            f"/api/leads/{lead_id}/builder-prompt",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(generated.status_code, 200, generated.text)
        self.assertIn("restaurant website", generated.json()["prompt"].lower())

    def test_gmail_status_explicitly_excludes_inbox_reading(self):
        client, _ = self._registered_client()
        status = client.get("/api/integrations/gmail/status")
        self.assertEqual(status.status_code, 200)
        capability = status.json()["capability"].lower()
        self.assertIn("does not read", capability)
        self.assertIn("no send endpoint", capability)

    def test_research_keyword_matches_meaningful_words_not_whole_phrase(self):
        tags = {"name": "Test Italian Restaurant", "amenity": "restaurant", "cuisine": "italian"}
        self.assertTrue(mcas.research_keyword_matches(tags, "Italian restaurants"))
        self.assertTrue(mcas.research_keyword_matches(tags, "businesses that need websites"))
        self.assertFalse(mcas.research_keyword_matches(tags, "dental clinic"))

    def test_public_contact_email_selects_first_valid_listed_address(self):
        tags = {"contact:email": "not-an-email; hello@example.org; second@example.org"}
        self.assertEqual(mcas.public_contact_email(tags), "hello@example.org")

    def test_candidate_priority_prefers_public_contact_and_unlisted_website(self):
        without_site = {"name": "A", "email": "owner@example.org", "phone": "+254700000000"}
        with_site = {"name": "B", "website": "https://example.org"}
        self.assertGreater(mcas.research_candidate_priority(without_site),
                           mcas.research_candidate_priority(with_site))

    def test_education_business_gets_education_builder_prompt(self):
        client, csrf = self._registered_client()
        lead = client.post(
            "/api/leads",
            json={"name": "Test School", "market": "Nairobi",
                  "evidence": "OpenStreetMap category amenity: school."},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(lead.status_code, 201, lead.text)
        lead_id = lead.json()["id"]
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        accepted = client.patch(
            f"/api/leads/{lead_id}",
            json={"name": "Test School", "website": None, "market": "Nairobi",
                  "evidence": "OpenStreetMap category amenity: school.", "status": "Won",
                  "contact_email": None, "contact_phone": None, "source_url": None,
                  "do_not_contact": False},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        generated = client.post(f"/api/leads/{lead_id}/builder-prompt",
                                headers={"X-CSRF-Token": csrf})
        self.assertEqual(generated.status_code, 200, generated.text)
        self.assertIn("education and training website", generated.json()["prompt"].lower())

    def test_overpass_query_uses_geocoded_bounding_box(self):
        query = mcas.overpass_query_for("Nairobi", "restaurant", (-1.45, 36.65, -1.15, 37.05))
        self.assertIn("(-1.450000,36.650000,-1.150000,37.050000)", query)
        self.assertNotIn("area.searchArea", query)

    def test_overpass_location_input_cannot_inject_query_syntax(self):
        query = mcas.overpass_query_for('Nairobi"];(node["name"~".*', "restaurant")
        self.assertIn('area["name"', query)
        self.assertNotIn('"];', query)
        self.assertNotIn('node["name"', query)


if __name__ == "__main__":
    unittest.main()
