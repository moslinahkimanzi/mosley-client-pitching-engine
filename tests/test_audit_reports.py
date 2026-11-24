import unittest

from backend.audit_reports import audit_pdf_filename, build_audit_pdf


class AuditPdfTests(unittest.TestCase):
    def sample_report(self):
        return {
            "url": "https://example.test/",
            "checked_at": "2026-11-24T16:37:58+00:00",
            "pages_checked": 2,
            "elapsed_ms": 2100,
            "summary": {
                "health_score": 87,
                "unique_findings": 2,
                "page_occurrences": 4,
                "detected_defects": 1,
                "potential_risks": 1,
                "unverified_observations": 0,
                "high": 1,
                "medium": 0,
                "low": 1,
                "info": 0,
                "total": 2,
            },
            "findings": [
                {
                    "code": "mixed_content",
                    "title": "HTTP resources were referenced by an HTTPS page",
                    "classification": "detected_defect",
                    "severity": "high",
                    "description": "One or more resources use HTTP on an HTTPS page.",
                    "evidence": "3 mixed-content references",
                    "evidence_by_page": [
                        {"url": "https://example.test/", "detail": "3 mixed-content references"}
                    ],
                    "affected_pages": ["https://example.test/", "https://example.test/about"],
                    "page_count": 2,
                    "recommendation": "Serve all page resources over HTTPS.",
                },
                {
                    "code": "missing_hsts",
                    "title": "Strict-Transport-Security header was not detected",
                    "classification": "potential_risk",
                    "severity": "low",
                    "description": "The response did not include an HSTS header.",
                    "evidence": None,
                    "evidence_by_page": [],
                    "affected_pages": ["https://example.test/"],
                    "page_count": 1,
                    "recommendation": "Consider enabling HSTS after checking subdomains.",
                },
            ],
            "recommendations": [
                {
                    "id": "secure_delivery",
                    "classification": "recommendation",
                    "title": "Secure delivery and asset remediation",
                    "priority": "high",
                    "description": "Review HTTPS and response security headers.",
                    "recommended_scope": [
                        "Replace HTTP resource references with valid HTTPS URLs.",
                        "Stage-test response headers.",
                    ],
                    "basis": "Derived from the detected audit findings.",
                }
            ],
            "pages": [
                {"url": "https://example.test/", "http_status": 200, "title": "Home", "response_time_ms": 850},
                {"url": "https://example.test/about", "http_status": 200, "title": "About", "response_time_ms": 900},
            ],
            "score_disclaimer": "Prioritisation indicator, not certification.",
            "scope_note": "Bounded static audit; no penetration test.",
            "limitations": ["JavaScript-rendered content may be missed."],
        }

    def test_generates_valid_pdf_signature_and_report_content(self):
        pdf = build_audit_pdf(self.sample_report())
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"WEBSITE TECHNICAL AUDIT", pdf)
        self.assertIn(b"DETECTED DEFECT", pdf)
        self.assertIn(b"POTENTIAL RISK", pdf)
        self.assertIn(b"Website improvement opportunities", pdf)
        self.assertIn(b"example.test", pdf)

        # Validate the PDF cross-reference table and every listed object offset.
        import re
        startxref_match = re.search(rb"startxref\s+(\d+)", pdf)
        self.assertIsNotNone(startxref_match)
        xref_offset = int(startxref_match.group(1))
        xref_lines = pdf[xref_offset:].splitlines()
        self.assertEqual(xref_lines[0], b"xref")
        first_object, object_count = xref_lines[1].split()
        self.assertEqual(first_object, b"0")
        object_count = int(object_count)
        object_entries = xref_lines[3:3 + object_count - 1]
        self.assertEqual(len(object_entries), object_count - 1)
        for object_id, entry in enumerate(object_entries, start=1):
            object_offset = int(entry[:10])
            self.assertTrue(
                pdf[object_offset:].startswith(f"{object_id} 0 obj".encode()),
                f"Bad PDF xref offset for object {object_id}",
            )

    def test_filename_is_host_based_and_sanitized(self):
        name = audit_pdf_filename(self.sample_report())
        self.assertEqual(name, "mcas-audit-example.test-20261124.pdf")


if __name__ == "__main__":
    unittest.main()
