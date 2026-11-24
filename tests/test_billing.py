import os
import unittest
import json
import uuid
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app as mcas


class BillingTest(unittest.TestCase):
    def setUp(self):
        with mcas.db() as connection:
            connection.execute('DELETE FROM security_rate_limits')

    def _client(self):
        client = TestClient(mcas.app)
        csrf = client.get("/api/auth/csrf").json()["csrf_token"]
        email = "billing-test-" + uuid.uuid4().hex + "@example.test"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "UniqueStrongPassphrase!2026"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return client, client.get("/api/auth/csrf").json()["csrf_token"]

    def test_new_account_has_free_credits_and_catalogue(self):
        client, _ = self._client()
        response = client.get("/api/billing/status")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["plan"], "free")
        self.assertEqual(data["monthly_credits"], 20)
        self.assertEqual(data["purchased_credits"], 0)
        self.assertIn("growth", data["plans"])
        self.assertIn("standard", data["credit_packs"])
        self.assertFalse(data["billing_enabled"])

    def test_checkout_is_disabled_without_public_provider_configuration(self):
        client, csrf = self._client()
        with patch.dict(os.environ, {"MCAS_PUBLIC_URL": "", "FLW_SECRET_KEY": "", "FLW_SECRET_HASH": ""}):
            response = client.post(
                "/api/billing/checkout",
                json={"item_type": "subscription", "item_code": "starter", "payment_method": "mpesa",
                      "phone_number": "+254712345678"},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 503, response.text)

    def test_checkout_rejects_client_selected_amount_and_unknown_sku(self):
        client, csrf = self._client()
        response = client.post(
            "/api/billing/checkout",
            json={"item_type": "subscription", "item_code": "999999", "amount": 1},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 422)

    def test_credit_debit_is_atomic_and_uses_monthly_before_purchased(self):
        client, _ = self._client()
        user_id = client.get("/api/auth/me").json()["id"]
        client.get("/api/billing/status")
        with mcas.db() as connection:
            connection.execute(
                "UPDATE billing_accounts SET monthly_credits=3,purchased_credits=10 WHERE user_id=?",
                (user_id,),
            )
        mcas.debit_credits(user_id, 5, "test_usage")
        with mcas.db() as connection:
            row = connection.execute("SELECT monthly_credits,purchased_credits FROM billing_accounts WHERE user_id=?",
                                     (user_id,)).fetchone()
        self.assertEqual((row["monthly_credits"], row["purchased_credits"]), (0, 8))
        with self.assertRaises(Exception):
            mcas.debit_credits(user_id, 20, "overdraw_test")
        with mcas.db() as connection:
            row = connection.execute("SELECT monthly_credits,purchased_credits FROM billing_accounts WHERE user_id=?",
                                     (user_id,)).fetchone()
        self.assertEqual((row["monthly_credits"], row["purchased_credits"]), (0, 8))

    def test_verified_credit_pack_order_grants_once(self):
        client, _ = self._client()
        user_id = client.get("/api/auth/me").json()["id"]
        order_id = uuid.uuid4().hex
        tx_ref = "MCAS-TEST-" + uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO billing_orders(id,user_id,tx_ref,item_type,item_code,amount_kes,currency,status,created_at,updated_at)
                   VALUES(?,?,?,'credits','small',1500,'KES','pending',?,?)""",
                (order_id, user_id, tx_ref, mcas.now(), mcas.now()),
            )
        self.assertTrue(mcas.grant_verified_order(order_id, "test-provider-transaction-1"))
        self.assertFalse(mcas.grant_verified_order(order_id, "test-provider-transaction-1"))
        with mcas.db() as connection:
            account = connection.execute("SELECT purchased_credits FROM billing_accounts WHERE user_id=?",
                                         (user_id,)).fetchone()
        self.assertEqual(account["purchased_credits"], 100)

    def test_paid_subscription_grants_allowance_and_expiry_downgrades(self):
        client, _ = self._client()
        user_id = client.get("/api/auth/me").json()["id"]
        order_id = uuid.uuid4().hex
        tx_ref = "MCAS-PLAN-" + uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO billing_orders(id,user_id,tx_ref,item_type,item_code,amount_kes,currency,status,created_at,updated_at)
                   VALUES(?,?,?,'subscription','starter',2500,'KES','pending',?,?)""",
                (order_id, user_id, tx_ref, mcas.now(), mcas.now()),
            )
        self.assertTrue(mcas.grant_verified_order(order_id, "test-plan-transaction"))
        with mcas.db() as connection:
            connection.execute("UPDATE billing_accounts SET period_end='2000-01-01T00:00:00+00:00' WHERE user_id=?", (user_id,))
        status = client.get("/api/billing/status").json()
        self.assertEqual(status["plan"], "free")
        self.assertEqual(status["monthly_credits"], 20)

    def test_webhook_amount_mismatch_does_not_grant_credits(self):
        client, _ = self._client()
        user_id = client.get("/api/auth/me").json()["id"]
        client.get("/api/billing/status")
        order_id = uuid.uuid4().hex
        tx_ref = "MCAS-WRONG-AMOUNT-" + uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO billing_orders(id,user_id,tx_ref,item_type,item_code,amount_kes,currency,status,created_at,updated_at)
                   VALUES(?,?,?,'credits','small',1500,'KES','pending',?,?)""",
                (order_id, user_id, tx_ref, mcas.now(), mcas.now()),
            )
        verified = {"status":"success","data":{"status":"successful","tx_ref":tx_ref,"currency":"KES","amount":1600}}
        payload = {"id":"evt-"+uuid.uuid4().hex,"type":"charge.completed",
                   "data":{"id":987655,"tx_ref":tx_ref,"status":"succeeded"}}
        with patch.dict(os.environ,{"FLW_SECRET_HASH":"test-secret"}), patch.object(mcas,"flutterwave_request",return_value=verified):
            response = client.post("/api/billing/flutterwave/webhook",json=payload,headers={"verif-hash":"test-secret"})
        self.assertEqual(response.status_code,400)
        with mcas.db() as connection:
            account = connection.execute("SELECT purchased_credits FROM billing_accounts WHERE user_id=?",(user_id,)).fetchone()
            order = connection.execute("SELECT status FROM billing_orders WHERE id=?",(order_id,)).fetchone()
        self.assertEqual(account["purchased_credits"],0)
        self.assertEqual(order["status"],"pending")

    def test_webhook_requires_shared_secret_hash(self):
        client, _ = self._client()
        with patch.dict(os.environ, {"FLW_SECRET_HASH": "correct-secret"}):
            response = client.post(
                "/api/billing/flutterwave/webhook",
                json={"event": "charge.completed", "data": {"id": 123, "tx_ref": "unknown"}},
                headers={"verif-hash": "wrong-secret"},
            )
        self.assertEqual(response.status_code, 401)

    def test_webhook_verifies_transaction_before_granting(self):
        client, _ = self._client()
        user_id = client.get("/api/auth/me").json()["id"]
        order_id = uuid.uuid4().hex
        tx_ref = "MCAS-WEBHOOK-" + uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO billing_orders(id,user_id,tx_ref,item_type,item_code,amount_kes,currency,status,created_at,updated_at)
                   VALUES(?,?,?,'credits','small',1500,'KES','pending',?,?)""",
                (order_id, user_id, tx_ref, mcas.now(), mcas.now()),
            )
        verified = {"status": "success", "data": {"status": "successful", "tx_ref": tx_ref,
                    "currency": "KES", "amount": 1500}}
        with patch.dict(os.environ, {"FLW_SECRET_HASH": "test-secret"}), patch.object(
            mcas, "flutterwave_request", return_value=verified
        ) as provider:
            payload = {"id": "evt-" + uuid.uuid4().hex, "event": "charge.completed",
                       "data": {"id": 987654, "tx_ref": tx_ref, "status": "successful"}}
            headers = {"verif-hash": "test-secret"}
            first = client.post("/api/billing/flutterwave/webhook", json=payload, headers=headers)
            second = client.post("/api/billing/flutterwave/webhook", json=payload, headers=headers)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["status"], "fulfilled")
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(provider.call_count, 1)
        with mcas.db() as connection:
            account = connection.execute("SELECT purchased_credits FROM billing_accounts WHERE user_id=?",
                                         (user_id,)).fetchone()
            order = connection.execute("SELECT status FROM billing_orders WHERE id=?", (order_id,)).fetchone()
        self.assertEqual(account["purchased_credits"], 100)
        self.assertEqual(order["status"], "paid")


if __name__ == "__main__":
    unittest.main()
