import os
import unittest
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app as mcas


class ResearchWorkflowTest(unittest.TestCase):
    def setUp(self):
        with mcas.db() as connection:
            connection.execute("DELETE FROM security_rate_limits")
        mcas._SERPER_CACHE.clear()

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

    def test_serper_places_research_saves_prospect_proposal_and_pending_email(self):
        client, csrf = self._registered_client()
        serper_response = {
            "places": [{
                "title": "Research Test Italian Restaurant",
                "address": "1 Test Road, Nairobi, Kenya",
                "category": "Italian restaurant",
                "phoneNumber": "+254700000000",
                "rating": 4.5,
                "ratingCount": 20,
                "cid": "123456789",
            }]
        }
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request", return_value=serper_response
        ) as mocked:
            response = client.post(
                "/api/research/run",
                json={
                    "location": "Nairobi",
                    "industry": "restaurant",
                    "keywords": "Italian",
                    "max_results": 6,
                },
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["saved"], 1)
        self.assertEqual(result["provider"], "Serper Places")
        self.assertEqual(result["resolved_location"], "Nairobi")
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["website_state"], "not_listed")
        self.assertGreaterEqual(result["results"][0]["opportunity_score"], 0)
        self.assertIn("highest_opportunity_score", result["summary"])
        self.assertFalse(result["results"][0]["proposal_created"])
        self.assertFalse(result["results"][0]["draft_created"])
        self.assertFalse(result["results"][0]["gmail_draft_created"])
        self.assertEqual(result["results"][0]["business_verification_status"], "unverified")
        self.assertIn("confirm", result["workflow"].lower())
        self.assertIn("Serper", result["results"][0]["evidence"])
        self.assertIn("does not prove", result["results"][0]["evidence"])
        self.assertIn("google.com/maps", result["results"][0]["source_url"])
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.args[0], "places")
        self.assertEqual(mocked.call_args.args[1]["gl"], "ke")
        self.assertEqual(mocked.call_args.args[1]["hl"], "en")
        self.assertIn("Italian", mocked.call_args.args[1]["q"])
        self.assertIn("Nairobi", mocked.call_args.args[1]["q"])

        self.assertEqual(len(client.get("/api/leads").json()), 1)
        self.assertEqual(len(client.get("/api/proposals").json()), 0)
        self.assertEqual(len(client.get("/api/drafts").json()), 0)

    def test_business_verification_requires_fresh_listing_and_human_confirmation(self):
        client, csrf = self._registered_client()
        created = client.post(
            "/api/leads",
            json={
                "name": "Verification Test Dental Clinic",
                "market": "Nairobi",
                "business_address": "1 Test Road, Nairobi, Kenya",
                "contact_phone": "+254700123456",
                "status": "Unverified",
                "evidence": "Initial discovery only.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(created.status_code, 201, created.text)
        lead_id = created.json()["id"]
        listing = {
            "places": [{
                "title": "Verification Test Dental Clinic",
                "address": "1 Test Road, Nairobi, Kenya",
                "phoneNumber": "+254700123456",
                "cid": "987654321",
            }]
        }
        web_results = {"organic": [{
            "title": "Verification Test Dental Clinic Nairobi",
            "link": "https://verification-test-clinic.example/about",
            "snippet": "Verification Test Dental Clinic at 1 Test Road, Nairobi. Contact +254700123456.",
        }]}
        with patch.object(
            mcas, "serper_request",
            side_effect=lambda endpoint, payload: listing if endpoint == "places" else web_results,
        ) as mocked:
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            checked = client.post(
                f"/api/leads/{lead_id}/verify-business",
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(checked.status_code, 200, checked.text)
        self.assertEqual(checked.json()["status"], "provider_reconfirmed")
        self.assertTrue(checked.json()["checks"]["business_name_match"])
        self.assertTrue(checked.json()["checks"]["address_match"])
        self.assertTrue(checked.json()["checks"]["phone_match"])
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(mocked.call_args_list[0].args[0], "places")
        self.assertEqual(mocked.call_args_list[1].args[0], "search")
        self.assertTrue(checked.json()["checks"]["independent_web_source"])
        self.assertEqual(len(checked.json()["independent_sources"]), 1)

        lead = next(item for item in client.get("/api/leads").json() if item["id"] == lead_id)
        self.assertEqual(lead["status"], "Unverified")
        self.assertEqual(lead["business_verification_status"], "provider_reconfirmed")

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        confirmed = client.post(
            f"/api/leads/{lead_id}/confirm-business",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        self.assertEqual(confirmed.json()["status"], "Verified")
        lead = next(item for item in client.get("/api/leads").json() if item["id"] == lead_id)
        self.assertEqual(lead["business_verification_status"], "human_confirmed")
        self.assertEqual(len(client.get("/api/proposals").json()), 1)
        drafts = client.get("/api/drafts").json()
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0]["state"], "pending_approval")
        self.assertIn("does not necessarily mean", drafts[0]["body"].lower())

    def test_identity_edits_invalidate_prior_business_verification(self):
        client, csrf = self._registered_client()
        created = client.post(
            "/api/leads",
            json={
                "name": "Identity Change Test Business",
                "market": "Nairobi",
                "business_address": "1 Test Road, Nairobi, Kenya",
                "contact_phone": "+254700123456",
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(created.status_code, 201, created.text)
        lead_id = created.json()["id"]
        listing = {"places": [{
            "title": "Identity Change Test Business",
            "address": "1 Test Road, Nairobi, Kenya",
            "phoneNumber": "+254700123456",
        }]}
        web_results = {"organic": [{
            "title": "Identity Change Test Business Nairobi",
            "link": "https://identity-change-test.example",
            "snippet": "Identity Change Test Business in Nairobi.",
        }]}
        with patch.object(
            mcas, "serper_request",
            side_effect=lambda endpoint, payload: listing if endpoint == "places" else web_results,
        ):
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            checked = client.post(
                f"/api/leads/{lead_id}/verify-business",
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(checked.json()["status"], "provider_reconfirmed")
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        client.post(
            f"/api/leads/{lead_id}/confirm-business",
            headers={"X-CSRF-Token": csrf},
        )
        lead = next(item for item in client.get("/api/leads").json() if item["id"] == lead_id)
        self.assertEqual(lead["status"], "Verified")

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        updated = client.patch(
            f"/api/leads/{lead_id}",
            json={
                "name": lead["name"], "website": lead["website"], "market": lead["market"],
                "business_address": lead["business_address"], "evidence": lead["evidence"],
                "status": "Verified", "contact_email": lead["contact_email"],
                "contact_phone": "+254711999999", "source_url": lead["source_url"],
                "do_not_contact": False,
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        lead = next(item for item in client.get("/api/leads").json() if item["id"] == lead_id)
        self.assertEqual(lead["status"], "Unverified")
        self.assertEqual(lead["business_verification_status"], "unverified")
        self.assertIsNone(lead["business_verified_at"])

    def test_business_verification_does_not_accept_a_name_only_match(self):
        client, csrf = self._registered_client()
        created = client.post(
            "/api/leads",
            json={
                "name": "Verification Test Dental Clinic",
                "market": "Nairobi",
                "business_address": "1 Test Road, Nairobi, Kenya",
                "contact_phone": "+254700123456",
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(created.status_code, 201, created.text)
        lead_id = created.json()["id"]
        listing = {"places": [{
            "title": "Verification Test Dental Clinic",
            "address": "99 Different Avenue, Mombasa, Kenya",
            "phoneNumber": "+254711999999",
        }]}
        web_results = {"organic": [{
            "title": "Verification Test Dental Clinic Nairobi",
            "link": "https://verification-test-clinic.example",
            "snippet": "Verification Test Dental Clinic in Nairobi.",
        }]}
        with patch.object(
            mcas, "serper_request",
            side_effect=lambda endpoint, payload: listing if endpoint == "places" else web_results,
        ):
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            checked = client.post(
                f"/api/leads/{lead_id}/verify-business",
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(checked.status_code, 200, checked.text)
        self.assertEqual(checked.json()["status"], "needs_manual_review")
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        rejected = client.post(
            f"/api/leads/{lead_id}/confirm-business",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(rejected.status_code, 409)

    def test_prospect_cannot_be_created_as_verified(self):
        client, csrf = self._registered_client()
        response = client.post(
            "/api/leads",
            json={"name": "Unverified Shortcut Test", "market": "Nairobi", "status": "Verified"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 409)

    def test_serper_web_search_returns_organic_results(self):
        client, _ = self._registered_client()
        preference_token = client.get("/api/auth/csrf").json()["csrf_token"]
        preferences = {
            "country_code": "US", "currency_code": "USD",
            "timezone": "America/New_York", "language_code": "es",
            "theme": "light", "pricing_multiplier": 2.2,
        }
        saved = client.put("/api/workspace/preferences", json=preferences,
                           headers={"X-CSRF-Token": preference_token})
        self.assertEqual(saved.status_code, 200, saved.text)
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request",
            return_value={"organic": [{"title": "Example salon", "link": "https://example.org", "snippet": "A salon"}]},
        ) as mocked:
            response = client.get("/api/research/search?q=salons+in+Nairobi")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["provider"], "Serper")
        self.assertEqual(result["results"][0]["url"], "https://example.org")
        mocked.assert_called_once_with("search", {"q": "salons in Nairobi", "num": 10, "gl": "us", "hl": "es"})

    def test_research_requires_serper_key(self):
        client, csrf = self._registered_client()
        with patch.dict(os.environ, {"SERPER_API_KEY": ""}):
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "salon", "max_results": 3},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn("SERPER_API_KEY", response.json()["detail"])

    def test_builder_prompt_requires_client_acceptance_and_uses_business_category(self):
        client, csrf = self._registered_client()
        lead = client.post(
            "/api/leads",
            json={
                "name": "Prompt Restaurant",
                "market": "Nairobi",
                "evidence": "Serper category: restaurant.",
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
                "evidence": "Serper category: restaurant.",
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

    def test_reply_assistant_prompt_is_persuasive_without_making_promises(self):
        prompt = mcas.assistant_system_prompt("reply").lower()
        self.assertIn("address their actual question", prompt)
        self.assertIn("never invent", prompt)
        self.assertIn("opt-out", prompt)
        self.assertIn("do-not-contact", prompt)
        self.assertIn("output only the reply body", prompt)

    def test_reply_prompt_requires_contextual_answers_not_generic_templates(self):
        prompt = mcas.assistant_system_prompt("reply").lower()
        self.assertIn("read the entire customer message", prompt)
        self.assertIn("do not use a generic template", prompt)
        self.assertIn("address every direct question", prompt)

    def test_research_generated_email_mentions_missing_website_carefully(self):
        subject, body = mcas.make_outreach_copy(
            "Example Salon", "Nairobi", "not_listed", {},
            {"type": "Salon website", "pages": ["Services", "Contact"]}, None
        )
        self.assertIn("Example Salon", subject)
        self.assertIn("does not necessarily mean", body.lower())
        self.assertIn("will not contact you again", body.lower())
        self.assertIn("\n\n", body)
        self.assertNotIn("\\n", body)


if __name__ == "__main__":
    unittest.main()
