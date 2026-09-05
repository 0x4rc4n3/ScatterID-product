import os
import sys
import json
import resource
import threading
import hashlib
import concurrent.futures
import unittest
from unittest.mock import patch, MagicMock

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

TEST_API_KEY = "test-crypto-load-dos-key"
os.environ["CRYPTO_SERVICE_API_KEY"] = TEST_API_KEY
os.environ["VAULT_DEV_MODE"] = "true"
os.environ["VAULT_TOKEN"] = "mock-vault-token"

from keygen import generate_keypair
from pq_sign import sign_data, verify_signature

initial_pub, initial_priv = generate_keypair("ML-DSA-65")
initial_pub_id = hashlib.sha256(initial_pub).hexdigest()[:32]

with patch("kms.KMS") as mock_kms_cls:
    mock_kms_inst = MagicMock()
    mock_kms_inst.lock = threading.RLock()
    mock_kms_inst.public_key_history = [initial_pub]
    mock_kms_inst.get_keys.return_value = (initial_pub, bytearray(initial_priv))
    mock_kms_cls.return_value = mock_kms_inst

    import app as crypto_app
    from app import app


class CryptoLoadDosTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        active_key = getattr(crypto_app, "API_KEY", TEST_API_KEY)
        self.auth_headers = {
            "Authorization": f"Bearer {active_key}",
            "Content-Type": "application/json"
        }

        # Reset keys in app and kms state to ensure test isolation
        crypto_app.PUBLIC_KEY = initial_pub
        crypto_app.PRIVATE_KEY = bytearray(initial_priv)
        crypto_app.PUBLIC_KEY_ID = initial_pub_id
        if not hasattr(crypto_app.kms, 'public_key_history') or not crypto_app.kms.public_key_history:
            crypto_app.kms.public_key_history = [initial_pub]
        elif initial_pub not in crypto_app.kms.public_key_history:
            crypto_app.kms.public_key_history.append(initial_pub)

        self.test_data = hashlib.sha3_256(b"scatterid-load-dos-benchmark").digest()
        self.test_hash = self.test_data.hex()
        self.test_sig = sign_data(self.test_data, initial_priv).hex()
        self.pub_key_id = initial_pub_id

    def test_oversized_payload_rejection_413(self):
        """Oversized payloads (> MAX_CONTENT_LENGTH) must be rejected with HTTP 413."""
        # 1.5MB body (exceeds default 1MB MAX_CONTENT_LENGTH)
        large_padding = "x" * (1500 * 1024)
        oversized_payload = json.dumps({
            "dataHash": self.test_hash,
            "padding": large_padding
        })

        resp = self.client.post(
            "/sign_hash",
            data=oversized_payload,
            headers=self.auth_headers
        )
        self.assertEqual(resp.status_code, 413)
        body = resp.get_json()
        self.assertEqual(body.get("code"), "PAYLOAD_TOO_LARGE")

        # Also test on /verify_hash
        oversized_verify = json.dumps({
            "dataHash": self.test_hash,
            "signature": self.test_sig,
            "publicKeyId": self.pub_key_id,
            "padding": large_padding
        })
        resp = self.client.post(
            "/verify_hash",
            data=oversized_verify,
            headers=self.auth_headers
        )
        self.assertEqual(resp.status_code, 413)
        body = resp.get_json()
        self.assertEqual(body.get("code"), "PAYLOAD_TOO_LARGE")

    def test_malformed_json_rejection_400(self):
        """Malformed JSON syntax must be rejected cleanly with HTTP 400."""
        malformed_body = '{"dataHash": "' + self.test_hash + '"'  # unclosed JSON
        resp = self.client.post(
            "/sign_hash",
            data=malformed_body,
            headers=self.auth_headers
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertEqual(body.get("code"), "BAD_REQUEST")

    def test_sustained_load_and_rss_memory_stability(self):
        """Execute sustained signing/verification cycles; confirm RSS memory remains stable."""
        # Initial RSS memory in KB
        initial_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        cycles = 150
        for i in range(cycles):
            # Sign
            sign_resp = self.client.post(
                "/sign_hash",
                json={"dataHash": self.test_hash},
                headers=self.auth_headers
            )
            self.assertEqual(sign_resp.status_code, 201)
            sign_data_res = sign_resp.get_json()
            sig = sign_data_res["signature"]
            pub_id = sign_data_res.get("publicKeyId", self.pub_key_id)

            # Verify
            verify_resp = self.client.post(
                "/verify_hash",
                json={
                    "dataHash": self.test_hash,
                    "signature": sig,
                    "publicKeyId": pub_id
                },
                headers=self.auth_headers
            )
            self.assertEqual(verify_resp.status_code, 200)
            self.assertTrue(verify_resp.get_json()["valid"])

        final_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_growth_mb = (final_rss_kb - initial_rss_kb) / 1024.0

        # Memory growth across 150 C sign/verify cycles must not exceed reasonable threshold (< 50MB)
        self.assertLess(
            rss_growth_mb,
            50.0,
            f"Unbounded memory leak detected: RSS grew by {rss_growth_mb:.2f} MB across {cycles} cycles"
        )

    def test_multithreaded_burst_concurrency(self):
        """Hammer crypto service with concurrent threads; verify thread safety and absence of torn reads."""
        num_workers = 15
        results = []

        def worker_task(idx):
            data_hash = hashlib.sha3_256(f"thread-worker-{idx}".encode()).hexdigest()
            # Sign
            resp = self.client.post(
                "/sign_hash",
                json={"dataHash": data_hash},
                headers=self.auth_headers
            )
            if resp.status_code != 201:
                return (False, f"Sign failed with status {resp.status_code}")
            resp_json = resp.get_json()
            sig = resp_json["signature"]
            pub_id = resp_json.get("publicKeyId", self.pub_key_id)

            # Verify
            vresp = self.client.post(
                "/verify_hash",
                json={
                    "dataHash": data_hash,
                    "signature": sig,
                    "publicKeyId": pub_id
                },
                headers=self.auth_headers
            )
            if vresp.status_code != 200 or not vresp.get_json().get("valid"):
                return (False, f"Verify failed for worker {idx}")

            return (True, "OK")

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_task, i) for i in range(num_workers)]
            for future in concurrent.futures.as_completed(futures):
                success, msg = future.result()
                self.assertTrue(success, msg)


if __name__ == "__main__":
    unittest.main()
