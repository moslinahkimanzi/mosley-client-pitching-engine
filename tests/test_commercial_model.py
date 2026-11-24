import unittest

from backend.intelligence import assess_website
from backend.commercial import PLANS, CREDIT_PACKS, CREDIT_COSTS, public_catalog


class CommercialModelTest(unittest.TestCase):
    def test_unknown_technical_signals_are_not_counted_as_failures(self):
        result = assess_website({}, "unknown")
        technical = result["technical_health"]
        self.assertIsNone(technical["score"])
        self.assertEqual(technical["coverage_percent"], 0)
        self.assertTrue(all(item["status"] == "unknown" for item in technical["findings"]))

    def test_known_html_signals_are_scored_with_coverage(self):
        result = assess_website({
            "http_status": 200, "content_type": "text/html",
            "title": "Example", "has_meta_description": True,
            "has_viewport_meta": True, "has_h1": True,
        }, "working", {"phone": "+254700000000", "email": "hello@example.com"})
        technical = result["technical_health"]
        self.assertEqual(technical["score"], 100)
        self.assertLess(technical["coverage_percent"], 100)  # TLS is deliberately unmeasured.
        self.assertTrue(any(x["status"] == "unknown" for x in technical["findings"]))

    def test_missing_listing_url_is_weak_signal_not_proof(self):
        result = assess_website({}, "not_listed")
        opportunity = result["commercial_opportunity"]
        self.assertIn("not a probability", opportunity["interpretation"])
        missing = next(x for x in opportunity["findings"] if "discovery listing" in x["signal"])
        self.assertEqual(missing["status"], "issue")
        self.assertIn("does not prove", missing["evidence"])

    def test_catalog_has_monthly_plans_and_one_time_credit_packs(self):
        self.assertEqual(set(PLANS), {"starter", "growth", "agency"})
        self.assertEqual(set(CREDIT_PACKS), {"mini", "standard", "pro"})
        self.assertGreater(CREDIT_COSTS["research_run"], 0)
        self.assertEqual(public_catalog()["currency"], "KES")


if __name__ == "__main__":
    unittest.main()
