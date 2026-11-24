import os
import unittest
import json
import uuid
import base64
import hashlib
import hmac
from unittest.mock import patch
from datetime import datetime, timezone
from decimal import Decimal

from fastapi.testclient import TestClient
from backend.commercial import payment_quote, public_catalog

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
        with patch.dict(os.environ, {"MCAS_PUBLIC_URL": "", "FLW_SECRET_KEY": "", "FLW_SECRET_HASH": "", "MCAS_BILLING_ENABLED": "false"}):
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
        verified = {"id":987655,"status":"successful","tx_ref":tx_ref,"currency":"KES","amount":1600}
        payload = {"id":"evt-"+uuid.uuid4().hex,"type":"charge.completed",
                   "data":{"id":987655,"tx_ref":tx_ref,"status":"succeeded"}}
        with patch.dict(os.environ,{"FLW_SECRET_HASH":"test-secret"}), patch.object(mcas,"verify_usd_transaction",return_value=verified):
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
        verified = {"id":987654,"status": "successful", "tx_ref": tx_ref,
                    "currency": "KES", "amount": 1500}
        with patch.dict(os.environ, {"FLW_SECRET_HASH": "test-secret"}), patch.object(
            mcas, "verify_usd_transaction", return_value=verified
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



    def test_usd_card_quote_stays_usd(self):
        quote = payment_quote(1200, "card")
        self.assertEqual(quote["provider_amount"], "12.00")
        self.assertEqual(quote["provider_currency"], "USD")
        self.assertIsNone(quote["exchange_rate"])

    def test_mpesa_quote_converts_usd_using_decimal_rounding(self):
        quote = payment_quote(1200, "mpesa", Decimal("130.25"))
        self.assertEqual(quote["provider_currency"], "KES")
        self.assertEqual(quote["provider_amount"], "1563")
        self.assertEqual(quote["amount_kes"], 1563)
        self.assertEqual(quote["exchange_rate"], "130.25")

    def test_mpesa_quote_rejects_missing_rate(self):
        with self.assertRaises(ValueError):
            payment_quote(1200, "mpesa", None)

    def test_checkout_uses_usd_for_card_and_stores_quote(self):
        client, csrf = self._client()
        user_id = client.get("/api/auth/me").json()["id"]
        future_date = datetime.now(timezone.utc).date().isoformat()
        env = {
            "MCAS_BILLING_ENABLED": "true", "FLW_SECRET_KEY": "test-key",
            "FLW_SECRET_HASH": "test-hash", "MCAS_PUBLIC_URL": "https://mcas.example.test",
            "MCAS_USD_KES_RATE": "130.00", "MCAS_USD_KES_RATE_DATE": future_date,
        }
        with patch.dict(os.environ, env), patch.object(mcas, "initialize_usd_checkout",
            return_value={"checkout_url": "https://checkout.flutterwave.com/test-session"}):
            response = client.post("/api/billing/checkout",
                json={"item_type":"subscription","item_code":"starter","payment_method":"card"},
                headers={"X-CSRF-Token":csrf})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["amount_usd"], "12.00")
        self.assertEqual(response.json()["provider_currency"], "USD")
        with mcas.db() as connection:
            order = connection.execute("SELECT * FROM billing_orders WHERE user_id=? ORDER BY created_at DESC LIMIT 1",(user_id,)).fetchone()
        self.assertEqual(order["provider_currency"], "USD")
        self.assertEqual(order["provider_amount"], "12.00")
        self.assertEqual(order["amount_usd_cents"], 1200)

    def test_mpesa_checkout_rejects_stale_fx_rate(self):
        client, csrf = self._client()
        env = {
            "MCAS_BILLING_ENABLED": "true", "FLW_SECRET_KEY": "test-key",
            "FLW_SECRET_HASH": "test-hash", "MCAS_PUBLIC_URL": "https://mcas.example.test",
            "MCAS_USD_KES_RATE": "130.00", "MCAS_USD_KES_RATE_DATE": "2020-01-01",
        }
        with patch.dict(os.environ, env):
            response = client.post("/api/billing/checkout",
                json={"item_type":"subscription","item_code":"starter","payment_method":"mpesa",
                      "phone_number":"+254712345678"},
                headers={"X-CSRF-Token":csrf})
        self.assertEqual(response.status_code, 503, response.text)


    def test_usd_card_webhook_grants_subscription_only_after_exact_verification(self):
        client, _ = self._client()
        user_id = client.get("/api/auth/me").json()["id"]
        order_id = uuid.uuid4().hex
        tx_ref = "MCAS-USD-" + uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO billing_orders
                   (id,user_id,tx_ref,item_type,item_code,amount_kes,currency,status,created_at,updated_at,
                    amount_usd_cents,provider_amount,provider_currency,payment_method)
                   VALUES(?,?,?,'subscription','starter',0,'USD','pending',?, ?,1200,'12.00','USD','card')""",
                (order_id,user_id,tx_ref,mcas.now(),mcas.now()),
            )
        verified = {
            "id": 246810, "status": "successful", "tx_ref": tx_ref,
            "currency": "USD", "amount": "12.00",
            "meta": {"customer_id":user_id,"item_type":"subscription","item_code":"starter",
                     "payment_method":"card","mcas_order_id":order_id},
        }
        event = {"id":"usd-event-"+uuid.uuid4().hex,"type":"charge.completed",
                 "data":{"id":246810,"tx_ref":tx_ref,"status":"successful"}}
        with patch.dict(os.environ,{"FLW_SECRET_HASH":"test-secret"}), patch.object(
            mcas,"verify_usd_transaction",return_value=verified
        ):
            response=client.post("/api/billing/flutterwave/webhook",json=event,headers={"verif-hash":"test-secret"})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()["status"],"fulfilled")
        with mcas.db() as connection:
            account=connection.execute("SELECT plan_code,monthly_credits FROM billing_accounts WHERE user_id=?",(user_id,)).fetchone()
            order=connection.execute("SELECT status,provider_transaction_id FROM billing_orders WHERE id=?",(order_id,)).fetchone()
        self.assertEqual(account["plan_code"],"starter")
        self.assertEqual(account["monthly_credits"],100)
        self.assertEqual(order["status"],"paid")
        self.assertEqual(order["provider_transaction_id"],"246810")

    def test_usd_webhook_rejects_wrong_currency_without_credit_grant(self):
        client, _ = self._client()
        user_id=client.get("/api/auth/me").json()["id"]
        # Materialise the free billing account before asserting that a rejected
        # payment leaves its credit balance unchanged.
        status_response = client.get("/api/billing/status")
        self.assertEqual(status_response.status_code, 200, status_response.text)
        order_id=uuid.uuid4().hex
        tx_ref="MCAS-USD-WRONG-"+uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO billing_orders
                   (id,user_id,tx_ref,item_type,item_code,amount_kes,currency,status,created_at,updated_at,
                    amount_usd_cents,provider_amount,provider_currency,payment_method)
                   VALUES(?,?,?,'credits','mini',0,'USD','pending',?, ?,500,'5.00','USD','card')""",
                (order_id,user_id,tx_ref,mcas.now(),mcas.now()),
            )
        verified={"id":135790,"status":"successful","tx_ref":tx_ref,"currency":"KES","amount":"5.00",
                  "meta":{"customer_id":user_id,"item_type":"credits","item_code":"mini",
                          "payment_method":"card","mcas_order_id":order_id}}
        event={"id":"wrong-currency-"+uuid.uuid4().hex,"data":{"id":135790,"tx_ref":tx_ref,"status":"successful"}}
        with patch.dict(os.environ,{"FLW_SECRET_HASH":"test-secret"}), patch.object(
            mcas,"verify_usd_transaction",return_value=verified
        ):
            response=client.post("/api/billing/flutterwave/webhook",json=event,headers={"verif-hash":"test-secret"})
        self.assertEqual(response.status_code,400)
        with mcas.db() as connection:
            account=connection.execute("SELECT purchased_credits FROM billing_accounts WHERE user_id=?",(user_id,)).fetchone()
            order=connection.execute("SELECT status FROM billing_orders WHERE id=?",(order_id,)).fetchone()
        self.assertEqual(account["purchased_credits"],0)
        self.assertEqual(order["status"],"pending")


    def test_webhook_accepts_flutterwave_hmac_signature(self):
        client, _ = self._client()
        raw = json.dumps({"id":"wbk-test","type":"charge.completed",
                          "data":{"id":12345,"tx_ref":"not-an-mcas-order","status":"successful"}},
                         separators=(",",":")).encode("utf-8")
        secret = "hmac-test-secret"
        signature = base64.b64encode(hmac.new(secret.encode(),raw,hashlib.sha256).digest()).decode()
        with patch.dict(os.environ,{"FLW_SECRET_HASH":secret}):
            response=client.post("/api/billing/flutterwave/webhook",content=raw,
                                 headers={"Content-Type":"application/json","flutterwave-signature":signature})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()["status"],"ignored")

    def test_usd_webhook_accepts_opaque_event_id_and_null_verified_metadata(self):
        client,_=self._client()
        user_id=client.get("/api/auth/me").json()["id"]
        order_id=uuid.uuid4().hex
        tx_ref="MCAS-OPAQUE-"+uuid.uuid4().hex
        with mcas.db() as connection:
            connection.execute(
                """INSERT INTO billing_orders
                   (id,user_id,tx_ref,item_type,item_code,amount_kes,currency,status,created_at,updated_at,
                    amount_usd_cents,provider_amount,provider_currency,payment_method)
                   VALUES(?,?,?,'credits','mini',0,'USD','pending',?, ?,500,'5.00','USD','card')""",
                (order_id,user_id,tx_ref,mcas.now(),mcas.now()),
            )
        verified={"id":765432,"status":"successful","tx_ref":tx_ref,"currency":"USD","amount":"5.00","meta":None}
        event={"id":"wbk-"+uuid.uuid4().hex,"type":"charge.completed",
               "data":{"id":"chg_opaque_identifier","reference":tx_ref,"status":"succeeded"}}
        with patch.dict(os.environ,{"FLW_SECRET_HASH":"test-secret"}), patch.object(
            mcas,"verify_usd_transaction",return_value=verified
        ) as verifier:
            response=client.post("/api/billing/flutterwave/webhook",json=event,headers={"verif-hash":"test-secret"})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()["status"],"fulfilled")
        verifier.assert_called_once_with("chg_opaque_identifier",tx_ref)
        with mcas.db() as connection:
            account=connection.execute("SELECT purchased_credits FROM billing_accounts WHERE user_id=?",(user_id,)).fetchone()
        self.assertEqual(account["purchased_credits"],30)


    def test_public_credit_costs_match_metering_catalogue(self):
        costs = public_catalog()["credit_costs"]
        self.assertEqual(costs["research"], 5)
        self.assertEqual(costs["business_recheck"], 3)
        self.assertEqual(costs["audit_1_5_pages"], 3)
        self.assertEqual(costs["audit_6_10_pages"], 5)
        self.assertEqual(costs["audit_11_15_pages"], 7)
        self.assertEqual(costs["competitors_1_3"], 6)
        self.assertEqual(costs["competitors_4_5"], 8)
        self.assertEqual(costs["competitors_6_8"], 11)
        self.assertEqual(costs["ai_generation"], 1)

if __name__ == "__main__":
    unittest.main()
