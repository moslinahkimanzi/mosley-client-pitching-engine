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

    def test_serper_places_research_saves_verified_business_but_not_unproven_opportunity(self):
        client, csrf = self._registered_client()
        places_response = {
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
        corroboration_response = {
            "organic": [{
                "title": "Research Test Italian Restaurant - Nairobi",
                "link": "https://research-test-restaurant.example/about",
                "snippet": "Research Test Italian Restaurant located at 1 Test Road, Nairobi, Kenya.",
            }]
        }
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request",
            side_effect=[places_response, corroboration_response],
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
        self.assertIn("independent Serper web corroboration", result["provider"])
        self.assertEqual(result["resolved_location"], "Nairobi")
        self.assertEqual(len(result["results"]), 1)
        prospect = result["results"][0]
        self.assertTrue(prospect["verified"])
        self.assertEqual(prospect["verification_status"], "verified")
        self.assertGreaterEqual(prospect["verification_score"], 80)
        self.assertEqual(prospect["website_state"], "not_listed")
        self.assertEqual(prospect["website_presence"], "no_website_found")
        self.assertTrue(prospect["validation_sample_id"])
        self.assertFalse(prospect["pitch_eligible"])
        self.assertFalse(prospect["proposal_created"])
        self.assertFalse(prospect["draft_created"])
        self.assertFalse(prospect["gmail_draft_created"])
        self.assertIn("Serper", prospect["evidence"])
        self.assertIn("does not prove", result["warning"])
        self.assertIn("google.com/maps", prospect["source_url"])
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(mocked.call_args_list[0].args[0], "places")
        self.assertEqual(mocked.call_args_list[1].args[0], "search")
        self.assertIn("Research Test Italian Restaurant", mocked.call_args_list[1].args[1]["q"])

        leads = client.get("/api/leads").json()
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["status"], "Verified")
        self.assertEqual(leads[0]["verification_status"], "verified")
        self.assertEqual(leads[0]["research_origin"], "serper_places")
        self.assertEqual(leads[0]["pitch_eligible"], 0)
        self.assertEqual(leads[0]["website_presence"], "no_website_found")
        samples = client.get("/api/quality/validation").json()
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["predicted_website_presence"], "no_website_found")
        self.assertEqual(client.get("/api/quality/metrics").json()["overall"]["samples"], 1)
        self.assertEqual(client.get("/api/proposals").json(), [])
        self.assertEqual(client.get("/api/drafts").json(), [])

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        blocked_draft = client.post(
            "/api/drafts",
            json={"lead_id": prospect["lead_id"], "kind": "Cold email", "subject": "Test", "body": "Test"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(blocked_draft.status_code, 409, blocked_draft.text)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        blocked_proposal = client.post(
            "/api/proposals",
            json={"lead_id": prospect["lead_id"], "title": "Test", "content": "Test"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(blocked_proposal.status_code, 409, blocked_proposal.text)

    def test_unverified_places_candidate_is_not_saved_or_pitched(self):
        client, csrf = self._registered_client()
        places_response = {
            "places": [{
                "title": "Uncorroborated Business",
                "address": "1 Unknown Road, Nairobi, Kenya",
                "category": "Restaurant",
            }]
        }
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request",
            side_effect=[places_response, {"organic": []}],
        ):
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 3},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["saved"], 0)
        self.assertEqual(result["summary"]["rejected_unverified_candidates"], 1)
        self.assertFalse(result["results"][0]["verified"])
        self.assertFalse(result["results"][0]["saved"])
        self.assertEqual(client.get("/api/leads").json(), [])
        self.assertEqual(client.get("/api/proposals").json(), [])
        self.assertEqual(client.get("/api/drafts").json(), [])

    def test_verification_provider_failure_withholds_candidates_without_retrying(self):
        client, csrf = self._registered_client()
        places_response = {
            "places": [{
                "title": "Verification Service Failure Test",
                "address": "1 Test Road, Nairobi, Kenya",
                "category": "Restaurant",
            }]
        }
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-serper-key"}), patch.object(
            mcas, "serper_request",
            side_effect=[places_response, mcas.HTTPException(503, "Serper verification quota unavailable")],
        ) as mocked:
            response = client.post(
                "/api/research/run",
                json={"location": "Nairobi", "industry": "restaurant", "max_results": 6},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(result["saved"], 0)
        self.assertEqual(result["results"][0]["verification_status"], "verification_unavailable")
        self.assertFalse(result["results"][0]["verified"])
        self.assertEqual(client.get("/api/leads").json(), [])
        self.assertEqual(client.get("/api/proposals").json(), [])
        self.assertEqual(client.get("/api/drafts").json(), [])

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
