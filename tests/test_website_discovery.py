import unittest

from backend.prospect_verification import find_business_website_candidate


class WebsiteDiscoveryTest(unittest.TestCase):
    def test_first_party_website_candidate_excludes_directory_platforms(self):
        results = [
            {"title": "Example Italian Restaurant - Nairobi",
             "link": "https://www.tripadvisor.com/Restaurant_Review/example",
             "snippet": "Example Italian Restaurant in Nairobi"},
            {"title": "Example Italian Restaurant",
             "link": "https://example-italian-restaurant.co.ke",
             "snippet": "Official website of Example Italian Restaurant in Nairobi"},
        ]
        candidate = find_business_website_candidate(
            "Example Italian Restaurant", "Nairobi",
            "Westlands, Nairobi, Kenya", results,
        )
        self.assertEqual(candidate, "https://example-italian-restaurant.co.ke")


if __name__ == "__main__":
    unittest.main()
