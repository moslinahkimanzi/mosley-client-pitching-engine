import unittest

from backend.prospect_verification import find_business_website_candidate
from backend.quality_metrics import (
    classify_research_group,
    select_balanced_research_results,
)


class BalancedResearchTest(unittest.TestCase):
    def test_working_identity_linked_website_is_classified(self):
        group = classify_research_group(
            {"status": "verified", "website_identity_match": True},
            "website_found",
            "working",
            {"http_status": 200},
        )
        self.assertEqual(group, "website_found")

    def test_bounded_no_website_result_is_classified_only_after_identity_verification(self):
        group = classify_research_group(
            {"status": "verified"},
            "no_website_found",
            "not_listed",
            {},
        )
        self.assertEqual(group, "no_website_found")
        self.assertIsNone(classify_research_group(
            {"status": "not_verified"},
            "no_website_found",
            "not_listed",
            {},
        ))

    def test_broken_website_requires_identity_link_and_two_confirmed_checks(self):
        base = {"status": "verified", "website_domain_corroborated": True}
        self.assertEqual(classify_research_group(
            base, "website_found", "broken", {"confirmed_unavailable_checks": 2}
        ), "broken_website")
        self.assertIsNone(classify_research_group(
            base, "website_found", "broken", {"confirmed_unavailable_checks": 1}
        ))
        self.assertIsNone(classify_research_group(
            {"status": "verified"}, "website_found", "broken",
            {"confirmed_unavailable_checks": 2},
        ))

    def test_balancer_selects_same_count_and_reports_shortfall(self):
        records = []
        for group, count in (
            ("website_found", 4),
            ("no_website_found", 3),
            ("broken_website", 2),
        ):
            for index in range(count):
                records.append({
                    "name": group + str(index),
                    "verified": True,
                    "saved": True,
                    "research_group": group,
                    "validation_sample_id": group + str(index),
                })
        result = select_balanced_research_results(records, 3)
        self.assertEqual(result["balanced_per_group"], 2)
        self.assertEqual(len(result["balanced_results"]), 6)
        counts = {}
        for item in result["balanced_results"]:
            counts[item["research_group"]] = counts.get(item["research_group"], 0) + 1
        self.assertEqual(counts, {
            "website_found": 2,
            "no_website_found": 2,
            "broken_website": 2,
        })
        self.assertEqual(result["shortfalls"]["broken_website"], 1)
        self.assertEqual(len(result["additional_results"]), 3)

    def test_balancer_never_uses_unverified_or_unsaved_candidates(self):
        result = select_balanced_research_results([
            {"verified": False, "saved": False, "research_group": "website_found"},
            {"verified": True, "saved": False, "research_group": "no_website_found"},
        ], 2)
        self.assertEqual(result["balanced_per_group"], 0)
        self.assertEqual(result["balanced_results"], [])

    def test_first_party_website_candidate_excludes_directory_platforms(self):
        results = [
            {
                "title": "Example Italian Restaurant - Nairobi",
                "link": "https://www.tripadvisor.com/Restaurant_Review/example",
                "snippet": "Example Italian Restaurant in Nairobi",
            },
            {
                "title": "Example Italian Restaurant",
                "link": "https://example-italian-restaurant.co.ke",
                "snippet": "Official website of Example Italian Restaurant in Nairobi",
            },
        ]
        candidate = find_business_website_candidate(
            "Example Italian Restaurant", "Nairobi",
            "Westlands, Nairobi, Kenya", results,
        )
        self.assertEqual(candidate, "https://example-italian-restaurant.co.ke")


if __name__ == "__main__":
    unittest.main()
