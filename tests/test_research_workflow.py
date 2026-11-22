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
        # Research tests exercise the local verification-link flow, not real SMTP.
        self.email_sender_patch = patch.object(mcas, "send_email_verification_message", return_value=False)
        self.email_sender_patch.start()
        self.addCleanup(self.email_sender_patch.stop)
        self.production_mode_patch = patch.object(mcas, "IS_PROD", False)
        self.production_mode_patch.start()
        self.addCleanup(self.production_mode_patch.stop)

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
        from urllib.parse import urlsplit, parse_qs
        verification_url = response.json().get("development_verification_url")
        self.assertTrue(verification_url, response.text)
        raw_token = parse_qs(urlsplit(verification_url).query)["verify_token"][0]
        confirmed = client.post("/api/auth/verify-email/confirm", json={"token": raw_token},
            headers={"X-CSRF-Token": client.get("/api/auth/csrf").json()["csrf_token"]})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        login = client.post("/api/auth/login",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": client.get("/api/auth/csrf").json()["csrf_token"]})
        self.assertEqual(login.status_code, 200, login.text)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        return client, csrf

    def test_research_auto_verifies_matching_first_party_website(self):
        client, csrf = self._registered_client()
        places = {"places": [{
            "title": "Acacia Garden Restaurant",
            "address": "Westlands, Nairobi, Kenya",
            "category": "Restaurant",
            "website": "https://acaciagarden.example",
            "phoneNumber": "+254700123456",
        }]}
        website = {
            "url": "https://acaciagarden.example",
            "http_status": 200,
            "content_type": "text/html",
            "title": "Acacia Garden Restaurant | Nairobi",
            "has_viewport_meta": True,
            "has_meta_description": True,
            "has_h1": True,
            "has_form": True,
        }
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request", return_value=places
        ) as mocked, patch.object(mcas, "safe_site_fetch", return_value=website) as fetch:
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 5},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(mocked.call_args.args[0], "places")
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(result["summary"]["verified_businesses"], 1)
        prospect = result["results"][0]
        self.assertTrue(prospect["verified"])
        self.assertEqual(prospect["verification_status"], "verified")
        self.assertEqual(prospect["website_state"], "working")
        self.assertEqual(prospect["website_presence"], "website_found")
        self.assertFalse(prospect["pitch_eligible"])
        self.assertEqual(result["research_limits"]["independent_web_searches"], 0)
        leads = client.get("/api/leads").json()
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["verification_status"], "verified")
        self.assertEqual(leads[0]["website_presence"], "website_found")
        self.assertEqual(client.get("/api/proposals").json(), [])
        self.assertEqual(client.get("/api/drafts").json(), [])

    def test_research_uses_bounded_independent_search_when_no_website_is_listed(self):
        client, csrf = self._registered_client()
        places = {"places": [{
            "title": "Kijani Garden Restaurant",
            "address": "Westlands, Nairobi, Kenya",
            "category": "Restaurant",
        }]}
        organic = {"organic": [
            {"title": "Kijani Garden Restaurant - Westlands",
             "link": "https://nairobi-food-review.example/kijani",
             "snippet": "Kijani Garden Restaurant in Westlands Nairobi"},
            {"title": "Kijani Garden Restaurant contact",
             "link": "https://local-eats-guide.example/kijani",
             "snippet": "Kijani Garden Restaurant located in Westlands Nairobi"},
        ]}
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request", side_effect=[places, organic]
        ) as mocked, patch.object(mcas, "safe_site_fetch") as fetch:
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 3},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual([call.args[0] for call in mocked.call_args_list], ["places", "search"])
        self.assertEqual(fetch.call_count, 0)
        prospect = result["results"][0]
        self.assertTrue(prospect["verified"])
        self.assertEqual(prospect["website_presence"], "no_website_found")
        self.assertEqual(prospect["website_state"], "not_listed")
        self.assertFalse(prospect["pitch_eligible"])
        self.assertEqual(result["research_limits"]["independent_web_searches"], 1)

    def test_research_marks_broken_only_after_two_confirmed_404_checks(self):
        client, csrf = self._registered_client()
        places = {"places": [{
            "title": "Acacia Garden Restaurant",
            "address": "Westlands, Nairobi, Kenya",
            "category": "Restaurant",
            "website": "https://acaciagarden.example",
        }]}
        organic = {"organic": [
            {"title": "Acacia Garden Restaurant Westlands",
             "link": "https://acaciagarden.example",
             "snippet": "Acacia Garden Restaurant in Westlands Nairobi"},
            {"title": "Acacia Garden Restaurant Nairobi listing",
             "link": "https://nairobi-eats-guide.example/acacia",
             "snippet": "Acacia Garden Restaurant in Westlands Nairobi"},
        ]}
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request", side_effect=[places, organic]
        ) as mocked, patch.object(
            mcas, "safe_site_fetch",
            side_effect=[
                {"url": "https://acaciagarden.example", "http_status": 404, "title": None},
                {"url": "https://acaciagarden.example", "http_status": 404, "title": None},
            ],
        ) as fetch:
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 1},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        prospect = response.json()["results"][0]
        self.assertTrue(prospect["verified"])
        self.assertEqual(prospect["website_state"], "broken")
        self.assertEqual(prospect["website_audit"]["confirmed_unavailable_checks"], 2)
        self.assertTrue(prospect["pitch_eligible"])
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(mocked.call_count, 2)

    def test_single_public_result_does_not_auto_verify_candidate(self):
        client, csrf = self._registered_client()
        places = {"places": [{
            "title": "Unconfirmed Test Restaurant",
            "address": "Westlands, Nairobi, Kenya",
            "category": "Restaurant",
        }]}
        organic = {"organic": [{
            "title": "Unconfirmed Test Restaurant",
            "link": "https://one-directory.example/business",
            "snippet": "Unconfirmed Test Restaurant in Westlands Nairobi",
        }]}
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request", side_effect=[places, organic]
        ):
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 1},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        prospect = response.json()["results"][0]
        self.assertFalse(prospect["verified"])
        self.assertEqual(prospect["verification_status"], "pending_manual_review")
        self.assertFalse(prospect["pitch_eligible"])
        lead = client.get("/api/leads").json()[0]
        self.assertEqual(lead["status"], "Unverified")
        self.assertEqual(lead["verification_status"], "pending_manual_review")

    def test_provider_failure_in_verification_does_not_crash_or_claim_broken(self):
        client, csrf = self._registered_client()
        places = {"places": [{
            "title": "Provider Timeout Restaurant",
            "address": "Westlands, Nairobi, Kenya",
            "category": "Restaurant",
        }]}
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request", side_effect=[places, mcas.HTTPException(502, "search unavailable")]
        ):
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 1},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        prospect = response.json()["results"][0]
        self.assertFalse(prospect["verified"])
        self.assertEqual(prospect["website_state"], "needs_review")
        self.assertFalse(prospect["pitch_eligible"])

    def test_marking_places_candidate_verified_records_manual_review(self):
        client, csrf = self._registered_client()
        places_response = {"places": [{
            "title": "Manual Review Test Business",
            "address": "1 Test Road, Nairobi, Kenya",
            "category": "Restaurant",
        }]}
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request", return_value=places_response
        ):
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 1},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        lead = client.get("/api/leads").json()[0]
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        payload = {
            "name": lead["name"], "website": "https://manual-review.example",
            "market": lead["market"], "evidence": "Manually checked the public listing and official website.",
            "status": "Verified", "contact_email": None, "contact_phone": None,
            "source_url": lead["source_url"], "do_not_contact": False,
        }
        updated = client.patch(
            "/api/leads/" + lead["id"], json=payload, headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        refreshed = client.get("/api/leads").json()[0]
        self.assertEqual(refreshed["verification_status"], "manual_reviewed")
        self.assertIsNotNone(refreshed["verified_at"])


    def test_quality_review_requires_evidence_and_is_workspace_private(self):
        client, csrf = self._registered_client()
        user_id = client.get("/api/auth/me").json()["id"]
        sample_id = uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO prospect_validation_samples(
                    id,user_id,business_name,industry,location,predicted_identity_verified,
                    predicted_website_presence,predicted_website_state,predicted_contact_email,
                    predicted_contact_phone,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sample_id,user_id,"Validation API Test","restaurant","Nairobi",1,
                 "website_found","working","contact@example.test","+254700000000",mcas.now(),mcas.now()),
            )
        payload = {
            "ground_truth_identity":"exists",
            "ground_truth_website_presence":"website_found",
            "ground_truth_website_state":"working",
            "ground_truth_email_correct":True,
            "ground_truth_phone_correct":False,
            "reviewer_evidence":"Independent official website checked on 2026-11-22: https://example.test",
            "reviewer_notes":"Test fixture only",
        }
        response = client.post(
            f"/api/quality/validation/{sample_id}",json=payload,
            headers={"X-CSRF-Token":csrf},
        )
        self.assertEqual(response.status_code,200,response.text)
        metrics = client.get("/api/quality/metrics").json()["overall"]
        self.assertEqual(metrics["identity_verification"]["true_positive"],1)
        self.assertEqual(metrics["website_status"]["accuracy"],1.0)
        self.assertEqual(metrics["contact_data"]["email"]["accuracy"],1.0)
        self.assertEqual(metrics["contact_data"]["phone"]["accuracy"],0.0)
        self.assertEqual(client.get("/api/quality/validation").json()[0]["reviewer_notes"],"Test fixture only")

        other_client, _ = self._registered_client()
        self.assertEqual(other_client.get("/api/quality/validation").json(),[])
        denied = other_client.post(
            f"/api/quality/validation/{sample_id}",json=payload,
            headers={"X-CSRF-Token":other_client.get("/api/auth/csrf").json()["csrf_token"]},
        )
        self.assertEqual(denied.status_code,404)

    def test_quality_review_rejects_missing_independent_evidence(self):
        client, csrf = self._registered_client()
        user_id = client.get("/api/auth/me").json()["id"]
        sample_id = uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO prospect_validation_samples(
                    id,user_id,business_name,industry,location,predicted_identity_verified,
                    predicted_website_presence,predicted_website_state,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (sample_id,user_id,"No Evidence Test","retail","Mombasa",0,"unknown","unknown",mcas.now(),mcas.now()),
            )
        response = client.post(
            f"/api/quality/validation/{sample_id}",
            json={"reviewer_evidence":"short"},
            headers={"X-CSRF-Token":csrf},
        )
        self.assertEqual(response.status_code,422)

    def test_serper_web_search_returns_organic_results(self):
        client, _ = self._registered_client()
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request",
            return_value={"organic": [{"title": "Example salon", "link": "https://example.org", "snippet": "A salon"}]},
        ) as mocked:
            response = client.get("/api/research/search?q=salons+in+Nairobi")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["provider"], "Serper")
        self.assertEqual(result["results"][0]["url"], "https://example.org")
        mocked.assert_called_once_with("search", {"q": "salons in Nairobi", "num": 10})

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
