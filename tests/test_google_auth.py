import json
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app as mcas


class _FakeGoogleResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _limit=-1):
        return self.payload


class GoogleOAuthTests(unittest.TestCase):
    def setUp(self):
        self.prod_patch = patch.object(mcas, "IS_PROD", False)
        self.prod_patch.start()
        self.addCleanup(self.prod_patch.stop)
        self.env_patch = patch.dict(os.environ, {
            "GOOGLE_OAUTH_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_OAUTH_CLIENT_SECRET": "test-client-secret",
            "GOOGLE_OAUTH_REDIRECT_URI": "http://testserver/api/auth/google/callback",
            "MCAS_ADMIN_EMAILS": "admin-google-test@example.test",
            "MCAS_ADMIN_BOOTSTRAP_TOKEN": "test-admin-bootstrap-token-which-is-long-enough-12345",
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        with mcas.db() as connection:
            connection.execute("DELETE FROM google_login_states")
            connection.execute("DELETE FROM security_rate_limits")

    def _start(self, email, bootstrap=""):
        client = TestClient(mcas.app, follow_redirects=False)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/google/start",
            json={"email": email, "admin_bootstrap_token": bootstrap},
            headers={"X-CSRF-Token": csrf},
        )
        return client, response

    def test_admin_bootstrap_is_required_only_for_first_admin_creation(self):
        _, denied = self._start("admin-google-test@example.test")
        self.assertEqual(denied.status_code, 403, denied.text)

        client, allowed = self._start(
            "admin-google-test@example.test",
            "test-admin-bootstrap-token-which-is-long-enough-12345",
        )
        self.assertEqual(allowed.status_code, 200, allowed.text)
        self.assertIn("accounts.google.com/o/oauth2/v2/auth", allowed.json()["authorization_url"])
        self.assertTrue(client.cookies.get("mcas_google_state"))

    def test_regular_customer_does_not_need_admin_bootstrap(self):
        _, response = self._start("ordinary-google-test@example.test")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("accounts.google.com/o/oauth2/v2/auth", response.json()["authorization_url"])

    def test_callback_creates_account_only_from_google_verified_identity(self):
        client, started = self._start("ordinary-google-test@example.test")
        self.assertEqual(started.status_code, 200, started.text)
        state = client.cookies.get("mcas_google_state")
        responses = [
            _FakeGoogleResponse({"access_token": "fake-access-token"}),
            _FakeGoogleResponse({
                "sub": "google-subject-test-123",
                "email": "ordinary-google-test@example.test",
                "email_verified": True,
            }),
        ]
        def fake_urlopen(*_args, **_kwargs):
            return responses.pop(0)

        with patch("backend.app.urllib.request.urlopen", side_effect=fake_urlopen):
            callback = client.get(
                "/api/auth/google/callback",
                params={"code": "one-time-test-code", "state": state},
            )
        self.assertEqual(callback.status_code, 303, callback.text)
        self.assertEqual(callback.headers.get("location"), "/")
        profile = client.get("/api/auth/me")
        self.assertEqual(profile.status_code, 200, profile.text)
        self.assertEqual(profile.json()["email"], "ordinary-google-test@example.test")

    def test_callback_rejects_missing_or_unverified_google_email(self):
        client, started = self._start("ordinary-google-test@example.test")
        state = client.cookies.get("mcas_google_state")
        responses = [
            _FakeGoogleResponse({"access_token": "fake-access-token"}),
            _FakeGoogleResponse({
                "sub": "google-subject-unverified",
                "email": "ordinary-google-test@example.test",
                "email_verified": False,
            }),
        ]
        def fake_urlopen(*_args, **_kwargs):
            return responses.pop(0)

        with patch("backend.app.urllib.request.urlopen", side_effect=fake_urlopen):
            callback = client.get(
                "/api/auth/google/callback",
                params={"code": "one-time-test-code", "state": state},
            )
        self.assertEqual(callback.status_code, 403, callback.text)


if __name__ == "__main__":
    unittest.main()
