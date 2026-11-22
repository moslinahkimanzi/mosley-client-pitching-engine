import unittest

from backend.prospect_verification import (
    name_match_score,
    qualify_website_opportunity,
    verify_candidate,
)


class ProspectVerificationTests(unittest.TestCase):
    def setUp(self):
        self.place = {
            "title": "Acacia Garden Restaurant",
            "address": "Westlands, Nairobi, Kenya",
            "category": "Restaurant",
            "phoneNumber": "+254700123456",
        }
        self.web_results = [{
            "title": "Acacia Garden Restaurant | Westlands Nairobi",
            "link": "https://acaciagarden.example/about",
            "snippet": "Acacia Garden Restaurant located in Westlands, Nairobi. Contact and dining information.",
        }]

    def test_normalises_business_names(self):
        self.assertEqual(name_match_score("Café Étoile Ltd", "Cafe Etoile - Nairobi"), 1.0)

    def test_requires_address_and_independent_corroboration(self):
        result = verify_candidate(
            self.place, "Nairobi", self.web_results,
            source_url="https://www.google.com/maps/search/?api=1&query=Acacia",
        )
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "verified")
        self.assertGreaterEqual(result["evidence_score"], 80)
        self.assertTrue(any(item["type"] == "public_web_result" for item in result["sources"]))

    def test_rejects_places_only_record(self):
        result = verify_candidate(
            self.place, "Nairobi", [],
            source_url="https://www.google.com/maps/search/?api=1&query=Acacia",
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "not_verified")

    def test_rejects_missing_address_even_if_name_matches(self):
        place = dict(self.place)
        place["address"] = ""
        result = verify_candidate(place, "Nairobi", self.web_results)
        self.assertFalse(result["verified"])

    def test_ignores_social_media_as_identity_corroboration(self):
        social = [{
            "title": "Acacia Garden Restaurant Nairobi",
            "link": "https://www.instagram.com/acacia",
            "snippet": "Acacia Garden Restaurant in Nairobi",
        }]
        result = verify_candidate(self.place, "Nairobi", social)
        self.assertFalse(result["verified"])

    def test_rejects_unrelated_name_or_location(self):
        unrelated = [{
            "title": "Acacia Garden Restaurant",
            "link": "https://unrelated.example",
            "snippet": "Acacia Garden Restaurant in Mombasa",
        }]
        result = verify_candidate(self.place, "Nairobi", unrelated)
        self.assertFalse(result["verified"])

    def test_closed_place_is_not_verified(self):
        place = dict(self.place, businessStatus="Permanently closed")
        result = verify_candidate(place, "Nairobi", self.web_results)
        self.assertFalse(result["verified"])
        self.assertTrue(result["closed"])

    def test_missing_website_is_not_pitch_opportunity(self):
        verification = {"status": "verified", "website_identity_match": False}
        eligible, reason = qualify_website_opportunity(verification, "not_listed", {})
        self.assertFalse(eligible)
        self.assertEqual(reason, "website_not_listed_is_not_proof_of_no_website")

    def test_broken_website_requires_two_confirmed_checks(self):
        verification = {"status": "verified", "website_identity_match": False}
        eligible, _ = qualify_website_opportunity(
            verification, "broken", {"confirmed_unavailable_checks": 1}
        )
        self.assertFalse(eligible)
        eligible, reason = qualify_website_opportunity(
            verification, "broken", {"confirmed_unavailable_checks": 2}
        )
        self.assertTrue(eligible)
        self.assertEqual(reason, "listed_website_returned_404_or_410_twice")

    def test_metadata_gap_requires_website_identity_match(self):
        verification = {"status": "verified", "website_identity_match": False}
        audit = {"has_viewport_meta": False}
        eligible, _ = qualify_website_opportunity(verification, "needs_improvement", audit)
        self.assertFalse(eligible)
        verification["website_identity_match"] = True
        eligible, reason = qualify_website_opportunity(verification, "needs_improvement", audit)
        self.assertTrue(eligible)
        self.assertEqual(reason, "confirmed_homepage_metadata_gaps")


if __name__ == "__main__":
    unittest.main()
