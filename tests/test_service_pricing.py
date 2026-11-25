import tempfile
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

import backend.app as mcas


class WorkspaceServicePricingTests(unittest.TestCase):
    def setUp(self):
        self.original_db_path = mcas.DB_PATH
        self.tempdir = tempfile.TemporaryDirectory(prefix="mcas-service-pricing-")
        mcas.DB_PATH = Path(self.tempdir.name) / "test.sqlite3"
        mcas.init_db()

    def tearDown(self):
        mcas.DB_PATH = self.original_db_path
        self.tempdir.cleanup()

    def register(self, client):
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        email = "pricing-" + uuid.uuid4().hex + "@example.test"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return client.get("/api/auth/csrf").json()["csrf_token"]

    def test_catalogue_seeds_eight_services_for_each_workspace(self):
        with TestClient(mcas.app) as client:
            self.register(client)
            response = client.get("/api/workspace/service-prices")
            self.assertEqual(response.status_code, 200, response.text)
            data = response.json()
            self.assertEqual(len(data["items"]), 8)
            self.assertEqual(data["items"][0]["currency_code"], "KES")
            self.assertEqual(data["items"][-1]["price_unit"], "monthly")

    def test_saved_prices_are_tenant_scoped_and_returned_by_services_endpoint(self):
        with TestClient(mcas.app) as owner, TestClient(mcas.app) as other:
            csrf = self.register(owner)
            self.register(other)
            current = owner.get("/api/workspace/service-prices").json()
            items = [{
                "service_code": item["service_code"],
                "minimum_price": item["minimum_price"] + 1000,
                "maximum_price": (
                    item["maximum_price"] + 1000 if item["maximum_price"] is not None else None
                ),
                "price_unit": item["price_unit"],
            } for item in current["items"]]
            saved = owner.put(
                "/api/workspace/service-prices",
                json={"currency_code": "KES", "items": items},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(saved.status_code, 200, saved.text)
            public_view = owner.get("/api/services/pricing")
            self.assertEqual(public_view.status_code, 200)
            self.assertEqual(public_view.json()["items"][0]["minimum_price"], items[0]["minimum_price"])
            other_view = other.get("/api/workspace/service-prices").json()
            self.assertNotEqual(other_view["items"][0]["minimum_price"], items[0]["minimum_price"])

    def test_invalid_currency_and_incomplete_catalogue_are_rejected(self):
        with TestClient(mcas.app) as client:
            csrf = self.register(client)
            current = client.get("/api/workspace/service-prices").json()
            items = [{
                "service_code": item["service_code"],
                "minimum_price": item["minimum_price"],
                "maximum_price": item["maximum_price"],
                "price_unit": item["price_unit"],
            } for item in current["items"]]
            bad_currency = client.put(
                "/api/workspace/service-prices",
                json={"currency_code": "ZZZ", "items": items},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(bad_currency.status_code, 422)
            incomplete = client.put(
                "/api/workspace/service-prices",
                json={"currency_code": "KES", "items": items[:-1]},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(incomplete.status_code, 422)

    def test_maximum_must_not_be_below_minimum_and_duplicate_codes_are_rejected(self):
        with TestClient(mcas.app) as client:
            csrf = self.register(client)
            current = client.get("/api/workspace/service-prices").json()
            items = [{
                "service_code": item["service_code"],
                "minimum_price": item["minimum_price"],
                "maximum_price": item["maximum_price"],
                "price_unit": item["price_unit"],
            } for item in current["items"]]
            items[0]["maximum_price"] = items[0]["minimum_price"] - 1
            invalid_range = client.put(
                "/api/workspace/service-prices",
                json={"currency_code": "KES", "items": items},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(invalid_range.status_code, 422)
            items = items[1:] + [dict(items[1])]
            duplicate = client.put(
                "/api/workspace/service-prices",
                json={"currency_code": "KES", "items": items},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(duplicate.status_code, 422)

    def test_catalogue_requires_authentication_and_csrf_for_updates(self):
        with TestClient(mcas.app) as client:
            self.assertEqual(client.get("/api/workspace/service-prices").status_code, 401)
            csrf = self.register(client)
            current = client.get("/api/workspace/service-prices").json()
            items = [{
                "service_code": item["service_code"],
                "minimum_price": item["minimum_price"],
                "maximum_price": item["maximum_price"],
                "price_unit": item["price_unit"],
            } for item in current["items"]]
            denied = client.put(
                "/api/workspace/service-prices",
                json={"currency_code": "KES", "items": items},
            )
            self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
