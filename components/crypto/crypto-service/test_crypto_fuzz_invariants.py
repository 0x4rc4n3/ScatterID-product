import os
import sys
import json
import random
import string
import hashlib
import threading
import unittest
from unittest.mock import patch, MagicMock

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

TEST_API_KEY = "test-crypto-fuzz-key"
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

    def mock_rotate(algorithm="ML-DSA-65"):
        with mock_kms_inst.lock:
            pub, priv = generate_keypair(algorithm)
            if pub not in mock_kms_inst.public_key_history:
                mock_kms_inst.public_key_history.append(pub)
            return pub, bytearray(priv)

    mock_kms_inst.rotate_keys.side_effect = mock_rotate
    mock_kms_cls.return_value = mock_kms_inst

    import app as crypto_app
    from app import app

# Ensure global keys are set in app module
crypto_app.PUBLIC_KEY = initial_pub
crypto_app.PRIVATE_KEY = bytearray(initial_priv)
crypto_app.PUBLIC_KEY_ID = initial_pub_id


class CryptoFuzzInvariantsTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        active_key = getattr(crypto_app, "API_KEY", TEST_API_KEY)
        self.auth_headers = {
            "Authorization": f"Bearer {active_key}",
            "Content-Type": "application/json"
        }

        # Ensure rotate_keys returns (pub, priv) tuple
        def mock_rotate(algorithm="ML-DSA-65"):
            with getattr(crypto_app.kms, 'lock', threading.RLock()):
                pub, priv = generate_keypair(algorithm)
                if not hasattr(crypto_app.kms, 'public_key_history'):
                    crypto_app.kms.public_key_history = []
                if pub not in crypto_app.kms.public_key_history:
                    crypto_app.kms.public_key_history.append(pub)
                return pub, bytearray(priv)

        crypto_app.kms.rotate_keys.side_effect = mock_rotate

        crypto_app.PUBLIC_KEY = initial_pub
        crypto_app.PRIVATE_KEY = bytearray(initial_priv)
        crypto_app.PUBLIC_KEY_ID = initial_pub_id
        if not hasattr(crypto_app.kms, 'public_key_history') or not crypto_app.kms.public_key_history:
            crypto_app.kms.public_key_history = [initial_pub]
        elif initial_pub not in crypto_app.kms.public_key_history:
            crypto_app.kms.public_key_history.append(initial_pub)

        # Generate legitimate test payload
        self.legit_data = hashlib.sha3_256(b"scatterid-fuzz-invariants").digest()
        self.legit_hash = self.legit_data.hex()
        self.legit_sig = sign_data(self.legit_data, initial_priv)
        self.legit_sig_hex = self.legit_sig.hex()
        self.pub_key_id = initial_pub_id

    def test_property_pure_function_determinism(self):
        """Property: verify_signature is a purely functional invariant with zero state drift."""
        for i in range(200):
            res = verify_signature(self.legit_data, self.legit_sig, initial_pub)
            self.assertTrue(res, f"verify_signature returned False on iteration {i}")

    def test_property_cross_key_isolation(self):
        """Property: Signatures are strictly isolated per keypair; cross-verification must fail."""
        for _ in range(10):
            other_pub, other_priv = generate_keypair("ML-DSA-65")
            other_sig = sign_data(self.legit_data, other_priv)

            # Cross verification must fail
            self.assertFalse(verify_signature(self.legit_data, self.legit_sig, other_pub))
            self.assertFalse(verify_signature(self.legit_data, other_sig, initial_pub))

    def test_property_generative_fuzz_sign_hash(self):
        """Generative fuzzing against /sign_hash: zero 500 errors, strict validation."""
        rng = random.Random(421337)

        malformed_hashes = [
            "",
            "not-a-hash",
            "0" * 63,            # 63 chars (too short)
            "0" * 65,            # 65 chars (too long)
            "z" * 64,            # non-hex
            "0" * 63 + "g",      # 64 chars but invalid hex
            "\x00" * 64,         # null bytes
            "' OR 1=1; --",      # SQL injection string
            "../../etc/passwd",  # path traversal
            "0" * 10000,         # large input
            None,
            12345,
            {"nested": "object"}
        ]

        # Add 100 pseudo-randomly generated garbage strings
        for _ in range(100):
            str_len = rng.randint(0, 128)
            garbage = "".join(rng.choice(string.printable) for _ in range(str_len))
            malformed_hashes.append(garbage)

        for payload_hash in malformed_hashes:
            req_body = {"dataHash": payload_hash}
            resp = self.client.post(
                "/sign_hash",
                data=json.dumps(req_body),
                headers=self.auth_headers
            )

            # Invariant: Server must NEVER throw 500 unhandled exception
            self.assertIn(
                resp.status_code,
                [400, 422],
                f"Expected 400/422 for malformed hash {payload_hash!r}, got {resp.status_code}"
            )
            data = resp.get_json()
            self.assertIsInstance(data, dict)
            self.assertIn("error", data)

    def test_property_generative_fuzz_verify_hash(self):
        """Generative fuzzing against /verify_hash: zero 500 errors, deterministic rejection."""
        rng = random.Random(99942)

        for i in range(150):
            scenario = rng.randint(0, 4)

            if scenario == 0:
                # Fuzz dataHash
                fuzzed_hash = "".join(rng.choice("0123456789abcdefghijklmnopqrstuvwxyz!@#") for _ in range(rng.randint(0, 80)))
                body = {
                    "dataHash": fuzzed_hash,
                    "signature": self.legit_sig_hex,
                    "publicKeyId": self.pub_key_id
                }
            elif scenario == 1:
                # Fuzz signature length / content
                sig_bytes = bytearray(self.legit_sig)
                mutation_type = rng.randint(0, 2)
                if mutation_type == 0 and len(sig_bytes) > 1:
                    # Truncate by 1 or more bytes
                    sig_bytes = sig_bytes[:rng.randint(1, len(sig_bytes) - 1)]
                elif mutation_type == 1:
                    # Extend by random bytes
                    sig_bytes.extend(bytes([rng.randint(0, 255) for _ in range(rng.randint(1, 20))]))
                else:
                    # Bit-flip in place
                    pos = rng.randint(0, len(sig_bytes) - 1)
                    sig_bytes[pos] ^= (1 << rng.randint(0, 7))

                body = {
                    "dataHash": self.legit_hash,
                    "signature": sig_bytes.hex(),
                    "publicKeyId": self.pub_key_id
                }
            elif scenario == 2:
                # Fuzz publicKeyId
                fuzzed_kid = "".join(rng.choice(string.ascii_letters + string.digits + "../;'") for _ in range(rng.randint(1, 40)))
                body = {
                    "dataHash": self.legit_hash,
                    "signature": self.legit_sig_hex,
                    "publicKeyId": fuzzed_kid
                }
            elif scenario == 3:
                # Malformed types / missing fields
                body = {
                    "dataHash": 12345,
                    "signature": None,
                    "publicKeyId": True
                }
            else:
                # Empty or null payload
                body = {}

            resp = self.client.post(
                "/verify_hash",
                data=json.dumps(body),
                headers=self.auth_headers
            )

            # Invariant: Server must NEVER crash with 500
            self.assertIn(
                resp.status_code,
                [200, 400, 404, 422],
                f"Verify hash crashed with {resp.status_code} for body: {body}"
            )
            data = resp.get_json()
            if resp.status_code == 200:
                # If 200, verification result must be False for mutated signature
                self.assertFalse(data.get("valid"), f"Fuzzed payload unexpectedly validated: {body}")
            else:
                self.assertIn("error", data)

    def test_property_kms_rotation_multi_version_invariance(self):
        """Property: Rotating keys preserves historical verification determinism."""
        test_hash = hashlib.sha3_256(b"rotation-invariant-message").digest().hex()

        historical_records = []

        # Perform 5 consecutive rotations and sign under each key
        for rot in range(5):
            kid = crypto_app.PUBLIC_KEY_ID
            sign_resp = self.client.post(
                "/sign_hash",
                data=json.dumps({"dataHash": test_hash}),
                headers=self.auth_headers
            )
            self.assertEqual(sign_resp.status_code, 201)
            sig_hex = sign_resp.get_json()["signature"]
            historical_records.append((kid, sig_hex))

            # Trigger rotation
            rot_resp = self.client.post("/rotate", headers=self.auth_headers)
            self.assertEqual(rot_resp.status_code, 200)

        # Invariant: Every historical signature must still verify under its respective key_id
        for kid, sig_hex in historical_records:
            verify_resp = self.client.post(
                "/verify_hash",
                data=json.dumps({
                    "dataHash": test_hash,
                    "signature": sig_hex,
                    "publicKeyId": kid
                }),
                headers=self.auth_headers
            )
            self.assertEqual(verify_resp.status_code, 200)
            self.assertTrue(
                verify_resp.get_json().get("valid"),
                f"Signature under historical key {kid} failed verification after rotations"
            )


if __name__ == "__main__":
    unittest.main()
