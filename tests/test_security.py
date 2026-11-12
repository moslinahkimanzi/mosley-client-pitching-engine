import unittest
from fastapi import HTTPException
from backend.app import password_hash, verify_password, token_hash, public_ip

class SecurityHelpersTest(unittest.TestCase):
    def test_password_hash_uses_salt_and_verifies(self):
        first = password_hash("A-long-unique-passphrase-2026!")
        second = password_hash("A-long-unique-passphrase-2026!")
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("A-long-unique-passphrase-2026!", first))
        self.assertFalse(verify_password("wrong-password", first))

    def test_session_token_is_hashed(self):
        self.assertNotEqual(token_hash("session-token"), "session-token")
        self.assertEqual(token_hash("session-token"), token_hash("session-token"))

    def test_private_network_targets_are_rejected(self):
        with self.assertRaises(HTTPException):
            public_ip("localhost")

if __name__ == "__main__":
    unittest.main()
