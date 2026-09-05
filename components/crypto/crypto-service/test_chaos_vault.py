import os
import sys
import json
import threading
import unittest
from unittest.mock import patch, MagicMock

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

TEST_API_KEY = "test-crypto-chaos-key"
os.environ["CRYPTO_SERVICE_API_KEY"] = TEST_API_KEY
os.environ["VAULT_DEV_MODE"] = "true"
os.environ["VAULT_TOKEN"] = "mock-vault-token"

from keygen import generate_keypair
import kms

initial_pub, initial_priv = generate_keypair("ML-DSA-65")

with patch("kms.KMS") as mock_kms_cls:
    mock_kms_inst = MagicMock()
    mock_kms_inst.lock = threading.RLock()
    mock_kms_inst.public_key_history = [initial_pub]
    mock_kms_inst.get_keys.return_value = (initial_pub, bytearray(initial_priv))
    mock_kms_cls.return_value = mock_kms_inst

    import app as crypto_app
    from app import app


class VaultChaosTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        active_key = getattr(crypto_app, "API_KEY", TEST_API_KEY)
        self.auth_headers = {
            "Authorization": f"Bearer {active_key}",
            "Content-Type": "application/json"
        }

    def test_vault_unreachable_get_keys_fails_loudly(self):
        """KMS get_keys must fail loudly when Vault is unreachable, never falling back to stale keys."""
        mock_kms = kms.KMS.__new__(kms.KMS)
        mock_kms.lock = threading.RLock()
        mock_kms.secret_path = "scatterid/signing-key"
        mock_kms.public_key_history = []
        mock_kms.client = MagicMock()
        mock_kms.client.secrets.kv.v2.read_secret_version.side_effect = ConnectionError("Vault connection refused")

        with self.assertRaises(RuntimeError) as ctx:
            mock_kms.get_keys("ML-DSA-65")

        self.assertIn("Failed to retrieve active signing keys from Vault", str(ctx.exception))

    def test_vault_unreachable_during_rotation_fails_cleanly(self):
        """When Vault is unreachable during /rotate, microservice returns 500 without crashing."""
        original_side_effect = getattr(crypto_app.kms.rotate_keys, "side_effect", None)
        crypto_app.kms.rotate_keys.side_effect = RuntimeError("Vault connection reset during key rotation")

        try:
            resp = self.client.post("/rotate", headers=self.auth_headers)
            self.assertEqual(resp.status_code, 500)
            data = resp.get_json()
            self.assertEqual(data.get("code"), "ROTATION_FAILED")
            self.assertIn("error", data)
        finally:
            crypto_app.kms.rotate_keys.side_effect = original_side_effect

    def test_missing_signing_key_fails_closed(self):
        """If signing key is unavailable, /sign_hash fails closed with 500 rather than issuing dummy signature."""
        with crypto_app.state_lock:
            saved_priv = crypto_app.PRIVATE_KEY
            crypto_app.PRIVATE_KEY = None

        try:
            resp = self.client.post(
                "/sign_hash",
                data=json.dumps({"dataHash": "a" * 64}),
                headers=self.auth_headers
            )
            self.assertEqual(resp.status_code, 500)
            data = resp.get_json()
            self.assertEqual(data.get("code"), "SIGNING_FAILED")
            self.assertIn("Signing key not available", data.get("error"))
        finally:
            with crypto_app.state_lock:
                crypto_app.PRIVATE_KEY = saved_priv


if __name__ == "__main__":
    unittest.main()
