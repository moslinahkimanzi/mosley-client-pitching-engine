import unittest
import uuid
from fastapi.testclient import TestClient
from fastapi import HTTPException
from backend.app import app, password_hash, verify_password, csrf_signature, valid_csrf, resolve_public

class SecurityHelpersTest(unittest.TestCase):
    def test_password_hash_is_salted_and_verifies(self):
        password = "UniqueStrongPassphrase!2026"
        first = password_hash(password)
        second = password_hash(password)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password(password, first))
        self.assertFalse(verify_password("wrong-password", first))

    def test_csrf_signature(self):
        token = "nonce-value." + csrf_signature("nonce-value")
        self.assertTrue(valid_csrf(token))
        self.assertFalse(valid_csrf(token + "tampered"))

    def test_private_network_is_rejected(self):
        with self.assertRaises(HTTPException):
            resolve_public("127.0.0.1")

class ApiSecurityTest(unittest.TestCase):
    def csrf(self, client):
        response = client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        return response.json()["csrf_token"]

    def register(self, client):
        token = self.csrf(client)
        email = "mcas-test-" + uuid.uuid4().hex + "@example.test"
        response = client.post("/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": token})
        self.assertEqual(response.status_code, 201, response.text)
        return email

    def test_authentication_required_for_private_leads(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/leads").status_code, 401)

    def test_mutations_require_csrf(self):
        with TestClient(app) as client:
            self.register(client)
            response = client.post("/api/leads", json={"name": "No CSRF"})
            self.assertEqual(response.status_code, 403)

    def test_accounts_cannot_read_each_others_leads(self):
        with TestClient(app) as first:
            self.register(first)
            csrf = self.csrf(first)
            created = first.post("/api/leads",
                json={"name": "Tenant one private prospect", "market": "Kenya", "evidence": "manual test"},
                headers={"X-CSRF-Token": csrf})
            self.assertEqual(created.status_code, 201, created.text)
        with TestClient(app) as second:
            self.register(second)
            response = second.get("/api/leads")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), [])

    def test_security_headers_are_present(self):
        with TestClient(app) as client:
            response = client.get("/api/health")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
            self.assertIn("script-src 'self'", response.headers.get("Content-Security-Policy", ""))

if __name__ == "__main__":
    unittest.main()
