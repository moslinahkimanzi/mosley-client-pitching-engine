import unittest

from backend.audit_engine import advanced_site_audit


class AdvancedAuditTests(unittest.TestCase):
    def test_audits_root_and_same_host_pages_and_reports_findings(self):
        pages = {
            "https://example.test/": {
                "url": "https://example.test/", "http_status": 200,
                "content_type": "text/html", "title": "Example",
                "response_time_ms": 120, "has_viewport_meta": True,
                "has_meta_description": True, "has_h1": True, "has_lang": True,
                "images_total": 0, "images_missing_alt": 0, "forms_total": 0,
                "form_controls_total": 0, "form_controls_without_label": 0,
                "mixed_content_references": 0, "security_headers": {},
                "links": ["/about", "https://third-party.test/out"],
            },
            "https://example.test/about": {
                "url": "https://example.test/about", "http_status": 404,
                "content_type": "text/html", "title": None,
                "response_time_ms": 180, "has_viewport_meta": False,
                "has_meta_description": False, "has_h1": False, "has_lang": False,
                "images_total": 0, "images_missing_alt": 0, "forms_total": 0,
                "form_controls_total": 0, "form_controls_without_label": 0,
                "mixed_content_references": 0, "security_headers": {}, "links": [],
            },
        }
        fetched = []

        def fetcher(url):
            fetched.append(url)
            return pages[url]

        report = advanced_site_audit("https://example.test/", fetcher, max_pages=10)

        self.assertEqual(report["pages_checked"], 2)
        self.assertEqual(set(fetched), {"https://example.test/", "https://example.test/about"})
        self.assertEqual(report["summary"]["medium"], 1)
        self.assertTrue(any(item["code"] == "http_not_found" for item in report["findings"]))
        self.assertIn("penetration-test certification", report["scope_note"])

    def test_page_limit_is_bounded(self):
        def fetcher(url):
            return {
                "url": url, "http_status": 200, "content_type": "text/html",
                "title": "Example", "response_time_ms": 50,
                "has_viewport_meta": True, "has_meta_description": True,
                "has_h1": True, "has_lang": True, "images_total": 0,
                "images_missing_alt": 0, "forms_total": 0,
                "form_controls_total": 0, "form_controls_without_label": 0,
                "mixed_content_references": 0, "security_headers": {},
                "links": ["/a", "/b", "/c", "/d", "/e", "/f"],
            }

        report = advanced_site_audit("https://example.test/", fetcher, max_pages=100)
        self.assertLessEqual(report["pages_checked"], 15)
        self.assertEqual(report["pages_limit"], 15)


if __name__ == "__main__":
    unittest.main()
