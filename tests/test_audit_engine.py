import unittest

from backend.audit_engine import (
    CLASS_DETECTED,
    CLASS_RISK,
    CLASS_RECOMMENDATION,
    CLASS_UNVERIFIED,
    advanced_site_audit,
)


def page(url, links=None):
    return {
        "url": url,
        "http_status": 200,
        "content_type": "text/html; charset=utf-8",
        "title": None,
        "response_time_ms": 3400,
        "has_viewport_meta": False,
        "has_meta_description": False,
        "has_h1": False,
        "has_lang": False,
        "images_total": 5,
        "images_missing_alt": 2,
        "form_controls_total": 3,
        "form_controls_without_label": 2,
        "mixed_content_references": 3,
        "security_headers": {},
        "links": links or [],
    }


class AdvancedAuditClassificationTests(unittest.TestCase):
    def test_repeated_issue_codes_are_deduplicated_for_scoring(self):
        root = "https://example.test/"
        about = "https://example.test/about"

        one_page = advanced_site_audit(root, lambda url: page(url), max_pages=1)

        def fetcher(url):
            if url == root:
                return page(url, ["/about"])
            if url == about:
                return page(url)
            raise AssertionError("Unexpected URL fetched: " + url)

        two_pages = advanced_site_audit(root, fetcher, max_pages=2)

        self.assertEqual(one_page["summary"]["unique_findings"], two_pages["summary"]["unique_findings"])
        self.assertEqual(one_page["summary"]["health_score"], two_pages["summary"]["health_score"])
        self.assertEqual(two_pages["pages_checked"], 2)

        missing_description = next(
            item for item in two_pages["findings"] if item["code"] == "missing_meta_description"
        )
        self.assertEqual(missing_description["classification"], CLASS_DETECTED)
        self.assertEqual(missing_description["page_count"], 2)
        self.assertEqual(
            set(missing_description["affected_pages"]),
            {root, about},
        )
        self.assertEqual(two_pages["summary"]["page_occurrences"],
                         sum(item["page_count"] for item in two_pages["findings"]))

    def test_evidence_classes_are_distinct_and_recommendations_are_separate(self):
        result = advanced_site_audit(
            "https://example.test/",
            lambda url: page(url),
            max_pages=1,
        )
        classes_by_code = {item["code"]: item["classification"] for item in result["findings"]}

        self.assertEqual(classes_by_code["mixed_content"], CLASS_DETECTED)
        self.assertEqual(classes_by_code["missing_hsts"], CLASS_RISK)
        self.assertEqual(classes_by_code["form_controls_without_label"], CLASS_UNVERIFIED)
        self.assertEqual(classes_by_code["slow_response"], CLASS_UNVERIFIED)

        self.assertTrue(result["recommendations"])
        self.assertTrue(all(item["classification"] == CLASS_RECOMMENDATION
                            for item in result["recommendations"]))
        self.assertEqual(
            result["summary"]["detected_defects"],
            sum(item["classification"] == CLASS_DETECTED for item in result["findings"]),
        )
        self.assertEqual(
            result["summary"]["potential_risks"],
            sum(item["classification"] == CLASS_RISK for item in result["findings"]),
        )
        self.assertIn("Unique issue codes", result["summary"]["score_method"])

    def test_access_denied_response_is_unverified_not_a_confirmed_defect(self):
        data = page("https://example.test/private")
        data["http_status"] = 403
        result = advanced_site_audit(
            "https://example.test/private",
            lambda url: data,
            max_pages=1,
        )
        finding = next(item for item in result["findings"] if item["code"] == "http_error")
        self.assertEqual(finding["classification"], CLASS_UNVERIFIED)
        self.assertNotIn(finding["classification"], {CLASS_DETECTED, CLASS_RISK})


if __name__ == "__main__":
    unittest.main()
