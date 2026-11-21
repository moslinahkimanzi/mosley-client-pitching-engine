import unittest
from backend.advanced_audit import analyze_document


class AdvancedAuditTests(unittest.TestCase):
    def test_reports_static_findings_and_limitations(self):
        html = """<!doctype html><html lang="en"><head>
        <title>Example Business</title><meta name="description" content="Local service">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="canonical" href="https://example.com/">
        <meta property="og:title" content="Example"><meta property="og:description" content="A business">
        </head><body><h1>Example</h1><p>""" + ("Useful business information " * 30) + """</p>
        <a href="/contact">Contact us</a><a href="/privacy">Privacy</a>
        <img src="/hero.jpg" alt="Business front"><script type="application/ld+json">{}</script>
        </body></html>"""
        result = analyze_document(html, {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff", "referrer-policy": "strict-origin"
        }, "https://example.com/")
        self.assertEqual(result["observations"]["h1_count"], 1)
        self.assertEqual(result["observations"]["images_missing_alt"], 0)
        self.assertIn("transport_security_headers", result["scores"])
        self.assertGreater(result["overall_score"], 50)
        self.assertTrue(result["limitations"])

    def test_flags_review_items_without_claiming_exploit(self):
        result = analyze_document("<html><body><img src='x'><p>hello</p></body></html>", {}, "http://example.test")
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("HTTPS transport", titles)
        self.assertIn("Image alternative text", titles)
        self.assertTrue(all(item["status"] == "review" for item in result["findings"]))
        self.assertTrue(any("not proof" in item.lower() for item in result["limitations"]))


if __name__ == "__main__":
    unittest.main()
