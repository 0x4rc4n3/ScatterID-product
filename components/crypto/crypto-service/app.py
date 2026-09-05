import hmac
import os
import uuid
import re
import hashlib
import threading
from flask import Flask, request, jsonify
from kms import KMS, zeroize
from interface import issue_credential, verify_credential

app = Flask(__name__)
# Enforce body size limit to prevent volumetric memory exhaustion / DoS attacks
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 1024 * 1024))  # 1MB default

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "error": "Payload Too Large: request entity exceeds body size limit",
        "code": "PAYLOAD_TOO_LARGE"
    }), 413

@app.errorhandler(400)
def bad_request(error):
    msg = error.description if hasattr(error, 'description') and error.description else "Bad Request"
    return jsonify({
        "error": str(msg),
        "code": "BAD_REQUEST"
    }), 400

kms = KMS()
PUBLIC_KEY, PRIVATE_KEY = kms.get_keys()
PUBLIC_KEY_ID = hashlib.sha256(PUBLIC_KEY).hexdigest()[:32]  # 128-bit collision resistance

state_lock = threading.RLock()

API_KEY = os.environ.get("CRYPTO_SERVICE_API_KEY")
if not API_KEY:
    raise ValueError(
        "CRITICAL: CRYPTO_SERVICE_API_KEY is not configured. "
        "For security, the crypto-service cannot start without an API key."
    )

@app.before_request
def enforce_api_key():
    if request.path == "/healthz":
        return None
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized: Missing Bearer Token", "code": "UNAUTHORIZED"}), 401
    
    token = auth_header.split(" ")[1]
    if not hmac.compare_digest(token, API_KEY):
        return jsonify({"error": "Unauthorized: Invalid API Key", "code": "UNAUTHORIZED"}), 401

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok", "service": "crypto-service"}), 200

@app.route("/sign_hash", methods=["POST"])
def sign_hash_route():
    data = request.get_json()
    if not data or "dataHash" not in data:
        return jsonify({"error": "Missing 'dataHash' field", "code": "BAD_REQUEST"}), 400

    data_hash = data["dataHash"]
    if not isinstance(data_hash, str) or not re.match(r'^[0-9a-fA-F]{64}$', data_hash):
        return jsonify({"error": "Invalid parameter: dataHash must be a 64-character hex string", "code": "INVALID_PARAMETER"}), 400
        
    credential_id = data.get("credentialId")
    if not credential_id:
        credential_id = str(uuid.uuid4())

    with state_lock:
        local_priv = bytearray(PRIVATE_KEY) if PRIVATE_KEY else None
        local_pub_id = PUBLIC_KEY_ID

    if not local_priv:
        return jsonify({"error": "Signing key not available", "code": "SIGNING_FAILED"}), 500

    try:
        result = issue_credential(data_hash, local_priv, local_pub_id)
        result["credentialId"] = credential_id
        return jsonify(result), 201
    except Exception as e:
        app.logger.error("Signing failed", exc_info=True)
        return jsonify({"error": "Signing failed due to internal error", "code": "SIGNING_FAILED"}), 500
    finally:
        zeroize(local_priv)

@app.route("/verify_hash", methods=["POST"])
def verify_hash_route():
    data = request.get_json()
    if not data or "dataHash" not in data or "signature" not in data or "publicKeyId" not in data:
        return jsonify({"error": "Missing required fields", "code": "BAD_REQUEST"}), 400

    data_hash = data["dataHash"]
    signature = data["signature"]
    public_key_id = data["publicKeyId"]

    if not isinstance(data_hash, str) or not re.match(r'^[0-9a-fA-F]{64}$', data_hash):
        return jsonify({"error": "Invalid parameter: dataHash must be a 64-character hex string", "code": "INVALID_PARAMETER"}), 400

    if not isinstance(signature, str) or not re.match(r'^[0-9a-fA-F]+$', signature) or len(signature) % 2 != 0:
        return jsonify({"error": "Invalid parameter: signature must be a valid hex string", "code": "INVALID_PARAMETER"}), 400

    if not isinstance(public_key_id, str) or not re.match(r'^[0-9a-fA-F]{32}$', public_key_id):
        return jsonify({"error": "Invalid parameter: publicKeyId must be a 32-character hex string", "code": "INVALID_PARAMETER"}), 400

    with state_lock:
        local_pub_key = bytes(PUBLIC_KEY) if PUBLIC_KEY else None
        local_pub_key_id = PUBLIC_KEY_ID

    keys_to_test = []
    
    # Check if the requested key matches the current one
    if local_pub_key and public_key_id == local_pub_key_id:
        keys_to_test.append(local_pub_key)
        
    # Also check historical keys if necessary
    with kms.lock:
        for pk in getattr(kms, 'public_key_history', []):
            if hashlib.sha256(pk).hexdigest()[:32] == public_key_id and pk not in keys_to_test:
                keys_to_test.append(pk)
                
    if not keys_to_test:
        return jsonify({"valid": False, "reason": "publicKeyId not found in trusted registry"}), 200

    valid = False
    for pk in keys_to_test:
        if verify_credential(data_hash, signature, pk):
            valid = True
            break

    return jsonify({"valid": valid}), 200

@app.route("/rotate", methods=["POST"])
def rotate_route():
    global PUBLIC_KEY, PRIVATE_KEY, PUBLIC_KEY_ID
    try:
        with state_lock:
            old_priv = PRIVATE_KEY
            PUBLIC_KEY, PRIVATE_KEY = kms.rotate_keys()
            PUBLIC_KEY_ID = hashlib.sha256(PUBLIC_KEY).hexdigest()[:32]  # 128-bit collision resistance
            if old_priv:
                zeroize(old_priv)
        return jsonify({
            "message": "Keys rotated successfully",
            "publicKeyId": PUBLIC_KEY_ID
        }), 200
    except Exception as e:
        app.logger.error("Key rotation operation failed", exc_info=True)
        return jsonify({"error": "Key rotation operation failed", "code": "ROTATION_FAILED"}), 500

import subprocess

def ensure_certificates(cert_path, key_path, base_dir):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    certs_dir = os.path.dirname(cert_path)
    os.makedirs(certs_dir, exist_ok=True)
    script_path = os.path.abspath(os.path.join(base_dir, '../certs/generate_certs.sh'))

    if os.path.exists(script_path):
        try:
            subprocess.run(['bash', script_path], check=True)
            if os.path.exists(cert_path) and os.path.exists(key_path):
                return cert_path, key_path
        except Exception as err:
            print(f"WARNING: Certificate generation script failed: {err}", flush=True)

    try:
        # Note on Transport Security vs. Credential Layer PQC:
        # Internal microservice mTLS uses classical RSA-2048 certificates for channel encryption.
        # While the issued credentials themselves are permanently quantum-resistant via ML-DSA-65,
        # transport-layer traffic is subject to harvest-now-decrypt-later (HNDL) risks until
        # post-quantum TLS (e.g. Kyber/ML-KEM hybrids) is configured across microservice proxies.
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-out', cert_path, '-keyout', key_path, '-days', '365',
            '-subj', '/CN=localhost/O=ScatterID'
        ], check=True)
    except Exception as err:
        print(f"ERROR: Fallback certificate generation failed: {err}", flush=True)

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise RuntimeError(
            f"FATAL: Could not generate TLS certificates. "
            f"Expected cert at {cert_path} and key at {key_path}. "
            f"The crypto-service cannot start without valid TLS certificates."
        )

    return cert_path, key_path

if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    TARGET_CERT = '/app/certs/crypto-service.crt' if os.path.exists('/app/certs') else os.path.join(BASE_DIR, '../certs/crypto-service.crt')
    TARGET_KEY = '/app/certs/crypto-service.key' if os.path.exists('/app/certs') else os.path.join(BASE_DIR, '../certs/crypto-service.key')

    CERT_PATH, KEY_PATH = ensure_certificates(TARGET_CERT, TARGET_KEY, BASE_DIR)
    BUNDLE_PATH = os.path.join(os.path.dirname(CERT_PATH), 'bundle.crt')
    EFFECTIVE_CERT = BUNDLE_PATH if os.path.exists(BUNDLE_PATH) else CERT_PATH

    app.run(host='0.0.0.0', port=5001, debug=False, ssl_context=(EFFECTIVE_CERT, KEY_PATH))
