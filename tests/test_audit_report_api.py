import base64
import email
import json
import os
import unittest
import uuid
from email import policy
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app as mcas


class FakeGmailResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, size=-1):
        return b'{"id":"test-gmail-draft-id"}'


class AuditReportApiTests(unittest.TestCase):
    def setUp(self):
        with mcas.db() as connection:
            connection.execute("DELETE FROM security_rate_limits")

    def _registered_client(self):
        client = TestClient(mcas.app)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        email_address = "audit-report-" + uuid.uuid4().hex + "@example.test"
        response = client.post(
            "/api/auth/register",
            json={"email": email_address, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return client, client.get("/api/auth/csrf").json()["csrf_token"]

    def _sample_audit(self, url):
        return {
            "url": url,
            "checked_at": "2026-11-24T16:37:58+00:00",
            "pages_checked": 1,
            "elapsed_ms": 1200,
            "http_status": 200,
            "findings": [{
                "code": "mixed_content",
                "title": "HTTP resources were referenced by an HTTPS page",
                "classification": "detected_defect",
                "severity": "high",
                "description": "The inspected HTTPS page references HTTP resources.",
                "recommendation": "Serve referenced assets over HTTPS.",
                "affected_pages": [url],
                "evidence_by_page": [{"url": url, "detail": "2 mixed-content references"}],
                "page_count": 1,
                "evidence": "2 mixed-content references",
            }],
            "recommendations": [{
                "id": "secure_delivery",
                "classification": "recommendation",
                "title": "Secure delivery and asset remediation",
                "priority": "high",
                "description": "Review HTTPS resource delivery.",
                "recommended_scope": ["Replace HTTP resource references."],
                "basis": "Derived from the observed mixed-content finding.",
            }],
            "summary": {
                "total": 1,
                "unique_findings": 1,
                "page_occurrences": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
                "detected_defects": 1,
                "potential_risks": 0,
                "recommendations": 1,
                "unverified_observations": 0,
                "health_score": 85,
                "score_method": "Unique issue codes are counted once across all checked pages.",
            },
            "score_disclaimer": "This is a prioritisation indicator, not a certification.",
            "scope_note": "Bounded static public website audit; not a penetration test.",
            "limitations": ["Dynamic content was not tested."],
            "pages": [{
                "url": url,
                "http_status": 200,
                "content_type": "text/html",
                "title": "Example website",
                "response_time_ms": 1200,
            }],
        }

    def test_audit_pdf_download_and_gmail_draft_attachment(self):
        client, csrf = self._registered_client()
        website = "https://audit-report.example"
        lead_response = client.post(
            "/api/leads",
            json={
                "name": "Audit Report Example Business",
                "website": website,
                "market": "Nairobi",
                "status": "Unverified",
                "evidence": "Test prospect for the audit report API.",
                "contact_email": "client@example.test",
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(lead_response.status_code, 201, lead_response.text)
        lead_id = lead_response.json()["id"]

        with patch.object(
            mcas, "advanced_site_audit", return_value=self._sample_audit(website)
        ):
            audit_response = client.post(
                "/api/audit-website",
                json={"url": website, "lead_id": lead_id, "max_pages": 1},
                headers={"X-CSRF-Token": csrf},
            )

        self.assertEqual(audit_response.status_code, 200, audit_response.text)
        audit_data = audit_response.json()
        report_id = audit_data["report_id"]
        self.assertEqual(audit_data["business_name"], "Audit Report Example Business")
        self.assertEqual(audit_data["summary"]["unique_findings"], 1)

        pdf_response = client.get(f"/api/audit-reports/{report_id}/pdf")
        self.assertEqual(pdf_response.status_code, 200, pdf_response.text)
        self.assertEqual(pdf_response.headers["content-type"], "application/pdf")
        self.assertIn("attachment;", pdf_response.headers["content-disposition"])
        self.assertTrue(pdf_response.content.startswith(b"%PDF-1.4"))
        self.assertTrue(pdf_response.content.rstrip().endswith(b"%%EOF"))

        other_client, _ = self._registered_client()
        other_download = other_client.get(f"/api/audit-reports/{report_id}/pdf")
        self.assertEqual(other_download.status_code, 404)

        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        draft_response = client.post(
            "/api/drafts",
            json={
                "lead_id": lead_id,
                "kind": "Cold email",
                "to_email": "client@example.test",
                "subject": "Website improvement review",
                "body": "Hello, please find the attached technical website review.",
                "audit_report_id": report_id,
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(draft_response.status_code, 201, draft_response.text)
        draft_id = draft_response.json()["id"]

        captured = {}

        def fake_urlopen(request, timeout=20):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeGmailResponse()

        with patch.object(mcas, "gmail_access_token", return_value="test-access-token"), patch.object(
            mcas.urllib.request, "urlopen", side_effect=fake_urlopen
        ):
            gmail_response = client.post(
                f"/api/drafts/{draft_id}/gmail",
                headers={"X-CSRF-Token": client.get("/api/auth/csrf").json()["csrf_token"]},
            )

        self.assertEqual(gmail_response.status_code, 200, gmail_response.text)
        self.assertIn("PDF attached", gmail_response.json()["message"])
        payload = json.loads(captured["request"].data.decode("utf-8"))
        raw_message = base64.urlsafe_b64decode(payload["message"]["raw"] + "===")
        parsed_message = email.message_from_bytes(raw_message, policy=policy.default)
        attachments = [
            part for part in parsed_message.iter_attachments()
            if part.get_content_type() == "application/pdf"
        ]
        self.assertEqual(len(attachments), 1)
        self.assertTrue(attachments[0].get_filename().endswith(".pdf"))
        self.assertTrue(attachments[0].get_payload(decode=True).startswith(b"%PDF-1.4"))

        drafts = client.get("/api/drafts").json()
        saved_draft = next(item for item in drafts if item["id"] == draft_id)
        self.assertEqual(saved_draft["gmail_draft_id"], "test-gmail-draft-id")
        self.assertEqual(saved_draft["audit_report_id"], report_id)


if __name__ == "__main__":
    unittest.main()
