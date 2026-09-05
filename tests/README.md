# Test Suites & Verification Framework (`tests/`)

Automated testing framework, cross-language cryptographic parity tests, and unified local test runner for the **ScatterID** ecosystem.

---

## 1. Overview & Testing Philosophy

The test harness in `tests/` is designed to provide high-assurance verification of cryptographic primitives, API boundaries, and offline verifiers without requiring Docker daemon access, live blockchain networks, or cloud dependencies:

- **Offline-First Execution**: All unit and parity tests execute directly on bare-metal developer machines in air-gapped environments.
- **Cross-Language Consistency**: Guarantees that claim hashing, RFC 8785 canonicalization, and salt commitments produce bit-for-bit identical outputs across Python and JavaScript engines.
- **Post-Quantum Forgery Testing**: Exercises live ML-DSA-65 key generation, signing, positive verification, and deterministic rejection of single-byte bitflips and forged signatures.

---

## 2. Test Scripts Catalog

### 1. Cross-Language Parity Suite (`offline_verify_parity.test.sh`)
Validates that both the Node.js structural verifier (`tools/verify_offline.js`) and Python PQC verifier (`tools/verify_offline.py`) evaluate identical test vectors with matching behavioral semantics across 6 test stages:

| Stage | Scenario | Expected Outcome |
| :--- | :--- | :--- |
| **Stage 1** | Valid unauthenticated credential | Both verifiers succeed with pre-image commitment match |
| **Stage 2** | Tampered attribute claim payload | Both verifiers reject with HTTP/exit 1 commitment mismatch |
| **Stage 3** | Corrupted 16-byte salt | Both verifiers detect salt alteration and reject verification |
| **Stage 4** | Malformed JSON syntax / missing fields | Both verifiers reject malformed schema cleanly without unhandled exceptions |
| **Stage 5** | Live ML-DSA-65 signature verification | Python Level 2 engine verifies mathematical post-quantum signature against issuer public key |
| **Stage 6** | Single-byte signature corruption / forgery | Python Level 2 engine detects signature tampering and rejects forgery |

```bash
# Run the offline verifier parity suite
bash tests/offline_verify_parity.test.sh
```

---

### 2. RFC 8785 Canonicalization Parity Fuzzer (`fuzz_canonicalize_parity.py`)
Executes generative adversarial fuzzing across Python (`rfc8785` + zero-dependency fallback) and Node.js (official `canonicalize` npm package + `tools/verify_offline.js`):
- **5,000-Iteration Generative Combinatorial Parity Fuzz**: Synthesizes pseudo-random JSON objects with arbitrary nesting depths (1–8 levels), mixed types, and adversarial payloads.
- **Unicode Stress Vectors**: Evaluates right-to-left override markers (`\u202E`, `\u202D`), zero-width joiners (`\u200D`), emoji with skin-tone composites (`👨‍👩‍👧‍👦`, `👍🏽`), surrogate pairs, and multi-lingual character sets (Arabic, Hebrew, Cyrillic, Greek, Devanagari, CJK).
- **RFC 8785 §3.2.3 UTF-16 Key Sorting**: Verifies that astral plane keys (`U+10000` -> `\uD800\uDC00`) sort before high-BMP keys (`U+E000`), inverting standard Unicode codepoint order.
- **Numeric Boundary Testing**: Asserts IEEE 754 precision compliance at `Number.MAX_SAFE_INTEGER` (`9007199254740991`), `Number.MIN_SAFE_INTEGER`, negative zero (`-0.0` normalized to `0`), arbitrary decimal precision, and fixed-to-exponential thresholding (`1e-6` to `1e20`).
- **Fail-Fast Error Handling**: Asserts strict cross-language rejection of `NaN`, `Infinity`, and integers exceeding `2^53 - 1`.

```bash
# Run the 5,000-iteration canonicalization fuzzer
python3 tests/fuzz_canonicalize_parity.py
```

---

### 3. Cryptographic Tamper Sensitivity Suite (`test_tamper_sensitivity.py`)
Validates foundational mathematical invariants of NIST FIPS 204 (ML-DSA-65) and FIPS 202 (SHA3-256):
- **Pure Function Verification**: Asserts that `verify(hash, sig, pk)` is purely functional with zero internal state drift or memory leakage over repetitive iterations.
- **Exhaustive SHA3-256 Bit Flips**: Flips each of the 256 bits in the pre-image commitment hash individually, proving 100% rejection across all 256 single-bit mutations.
- **Exhaustive ML-DSA-65 Signature Bit Flips**: Flips each of the 26,472 bits in the 3,309-byte post-quantum signature, proving 100% rejection across all 26,472 single-bit mutations.
- **Public Key Bit Flips**: Systematically mutates bit positions across the 1,952-byte public key, confirming immediate cryptographic failure.
- **Off-by-One Container Boundaries**: Tests 3308B/3310B signatures and 1951B/1953B public keys, proving structural length validation fails cleanly before signature parsing.

```bash
# Run the cryptographic tamper-sensitivity suite
python3 tests/test_tamper_sensitivity.py
```

---

### 4. Differential Offline Verifier Suite (`differential_offline_verifier.test.sh`)
Differential test harness evaluating behavioral congruence and architectural segregation between `tools/verify_offline.js` and `tools/verify_offline.py`:
- **Authentic Credentials**: Both engines pass Level 1 pre-image commitments; Python executes Level 2 signature verification (`CRYPTOGRAPHICALLY VALID & AUTHENTIC`).
- **Tampered Claims & Salts**: Both engines reject altered attributes or corrupted salts with exit code 1 and identical diagnostics (`LEVEL 1 VERIFICATION FAILED`).
- **Container-Valid Forgeries**: Verifies structurally valid (3309B signature, 1952B public key) but cryptographically invalid payloads. Confirms Node.js explicitly warns `⚠ PRE-IMAGE COMMITMENT MATCH (UNAUTHENTICATED)` while Python detects the forgery and exits with code 1 (`SIGNATURE VERIFICATION FAILED`).

```bash
# Run the differential offline verifier suite
bash tests/differential_offline_verifier.test.sh
```

---

### 5. Authorization Truth Tables & Adversarial Permutations (§8)
Exhaustively enumerates all truth-table permutations across security boundaries:
- **Smart Contract (`scatterproof.go`)**: Exhaustively tests all 8 combinations of `(callerMSP == IssuerMSP, callerIssuer == originalIssuer, status == active)` for `RevokeProof`, and boolean clauses for `AnchorProof`.
- **Verification API Gateway (`server.js`)**: Tests all permutations of `requireBearerAuth` and `requireRevokeAuth`:
  - Enforces privilege separation: standard `VERIFICATION_API_KEY` cannot execute on-chain revocations (403 `REVOCATION_UNAUTHORIZED`).
  - Scoped header isolation: `X-Revoke-Key` alone is rejected by all bearer operator endpoints (401 `MISSING_AUTH`).
  - No OR-bypass: Sending invalid `X-Revoke-Key` alongside valid verification bearer token fails closed with 403 `REVOCATION_UNAUTHORIZED`.
- **Crypto Microservice (`app.py`)**: Tests HTTP bearer token parsing, whitespace handling, and timing-safe constant-time `hmac.compare_digest` validation.

---

### 6. Authorization Mutation Testing Framework (`mutation_auth.test.sh`) (§9)
Automated mutation testing harness that deliberately injects 14 architectural mutants into production authorization logic:
- **Chaincode Mutants (7)**: Inverts/bypasses MSP checks, issuer equality checks, status checks, and replay guards in `scatterproof.go`.
- **Gateway API Mutants (4)**: Inverts/bypasses timing-safe hash comparisons and revocation authorization guards in `server.js`.
- **Crypto Service Mutants (3)**: Inverts/bypasses HMAC API key comparison and route bypass conditions in `app.py`.
- **Validation**: Asserts a **100% mutant kill rate** (14/14 killed by test suites). Any mutant survival halts execution.

```bash
# Run the authorization mutation testing suite
bash tests/mutation_auth.test.sh
```

---

### 7. Concurrency, Race Conditions & In-Flight Key Rotation (§4)
Validates thread-safety, race prevention, and atomic state transitions under concurrent load:
- **Idempotency Race (`idempotency_race.test.js`)**: Fires 50 simultaneous `/issue` requests with identical `idempotencyKey` concurrently via `Promise.all`. Verifies exactly 1 request wins the DB insertion race while the remaining 49 receive the matching credential record (200 OK) with identical IDs, hashes, and signatures without SQLite constraint crashes or duplicate rows.
- **Double-Revoke Race (`double_revoke_race.test.js`)**: Fires concurrent `/revoke` calls against identical credentials. Verifies that the ledger and local SQLite registry converge to a single authoritative `revoked` state with consistent 200 OK responses, zero double-spend corruption, and zero 502/500 errors.
- **Crypto Key Rotation Mid-Flight (`test_rotation_race.py`)**: Spawns concurrent signer and verifier worker threads issuing continuous `/sign_hash` and `/verify_hash` requests while a background worker triggers live `/rotate` operations. Validates that `state_lock` prevents torn reads between `PUBLIC_KEY_ID` and `PRIVATE_KEY`, mutable bytearrays are copied prior to zeroization of the old key, and historical signatures remain verifiable against `kms.public_key_history`.
- **Reconciliation vs. Live Writes (`reconcile_race.test.js`)**: Concurrently executes `reconcileLedger` during batch `/issue` and `/revoke` operations. Verifies that in-flight `pending` issuances are skipped, zero double-anchoring occurs, and distributed timeout failures (ledger is `active` while API recorded `anchor_failed`) are automatically self-healed to `anchored`.
- **Chaincode Data Race Detection**: Runs `go test -race -v ./...` with Go's runtime race detector across all smart contract functions and concurrent goroutine harnesses (`TestChaincode_ConcurrentExecution_RaceDetection`).

---

### 8. Boundary & Edge-Case Mathematical Verification (`test_boundary_math.py`, `boundary_math.test.js`) (§3)
Evaluates cryptographic, structural, and numeric boundaries against international standards and adversarial inputs:
- **NIST CAVP SHA3-256 Official Test Vectors**: Validates claim and salt hashing against official NIST Cryptographic Algorithm Validation Program test vectors (0-bit empty string, 8-bit, 24-bit `"abc"`, 448-bit multi-block, and 1,000,000-repetition 1MB message). Guarantees exact FIPS 202 domain-padding compliance (`0x06`) across Python `hashlib` and Node.js `crypto`.
- **ML-DSA-65 Off-by-One Container Boundary Enforcement**: Validates strict rejection of truncated or overflowing containers before C library invocation: signatures strictly 3,309 bytes (rejects 3,308B and 3,310B), public keys strictly 1,952 bytes (rejects 1,951B and 1,953B).
- **Salt Boundary & Anomaly Hardening**: Evaluates extreme salt lengths from 1 byte to 1 megabyte (1,048,576 bytes). Enforces strict even-length hexadecimal validation across Python and JavaScript offline verifiers, preventing Node.js `Buffer.from(..., 'hex')` odd-length truncation vulnerabilities.
- **Gateway Integer & Limit Clamping**: Asserts robust sanitization of query limits on `/audit` (`limit=-999999999`, `-1`, `0`, `NaN`, `Infinity`, `1e400`, `999999`, SQL injection strings). Clamps all inputs to `[1, 200]` (default 50), preventing SQLite negative-limit pagination bypasses.
- **Smart Contract RFC 3339 Timestamp Boundaries**: Enforces strict `time.RFC3339Nano` parsing in `AnchorProof`, rejecting malformed ISO 8601 strings, missing timezones, impossible calendar dates (e.g. Feb 30), and dates outside the valid era [1970, 2100].

```bash
# Run the boundary math suite
python3 tests/test_boundary_math.py
```

---

### 9. Coverage-Guided Fuzzing & Property-Based Invariant Testing (`scatterproof_fuzz_test.go`, `fuzz_invariants.test.js`, `test_crypto_fuzz_invariants.py`) (§1, §2)
Asserts foundational system invariants across smart contract, gateway, and crypto services using native Go coverage fuzzing and `fast-check`:
- **Native Go Coverage-Guided Fuzzing (`go test -fuzz`)**: Evaluates `AnchorProof` and `RevokeProof` smart contract entrypoints with continuous libFuzzer mutation across 16 workers. Feeds arbitrary byte streams, boundary UUIDs, SQL meta-characters, null bytes, and corrupted hashes, asserting zero panics and strict invariant preservation.
- **Monotonic Revocation Invariant**: Rigorously verified across both chaincode and gateway layers. Proves that once a credential transitions to `revoked`, NO sequence of subsequent operations (re-anchoring, duplicate revocations, status queries, or retry-anchors) can ever reactivate or resurrect the proof.
- **Pure Function Verification Invariance**: Proves that verifying credentials or querying state is purely functional with zero world-state drift, zero memory leaks, and bit-for-bit reproducible results across hundreds of parallel and sequential invocations.
- **Generative HTTP Fuzzing with `fast-check`**: Generates 500+ randomized adversarial payloads against `/verify` and `/revoke` endpoints (testing SQL injection strings `' OR 1=1; --`, `DROP TABLE`, directory traversal `../../etc/passwd`, embedded null bytes `\x00`, 10KB inputs, and malformed types). Proves that the gateway fails closed with structured 400/404 responses and zero unhandled 500 errors.
- **Multi-Version Key Rotation Invariance**: Rotates KMS keys through multiple generations while signing payloads, asserting that all historical signatures remain deterministically verifiable against `kms.public_key_history`.

```bash
# Run native Go coverage fuzzing
cd components/blockchain/chaincode/src && go test -fuzz=FuzzAnchorProof -fuzztime=5s

# Run gateway property-based tests
cd components/verification-api && node --test tests/fuzz_invariants.test.js
```

---

### 10. Chaos, Timeout, Network Failure & Distributed Fault Injection (`chaos_faults.test.js`, `test_chaos_vault.py`) (§5)
Validates resilience and graceful degradation under network partitions, upstream hangs, distributed ambiguities, and connection exhaustion:
- **Upstream Crypto Service Timeout & Slow-Response Handling**: Evaluates `/verify` and `/issue` against unresponsive and lagging upstream services. Confirms that `AbortSignal.timeout` terminates hanging upstream requests promptly, returning clean HTTP 504 Gateway Timeout (`CRYPTO_SERVICE_TIMEOUT`) rather than hanging caller connections indefinitely.
- **TCP Connection Reset Mid-Response Fault Injection**: Injects abrupt TCP RST packets and socket destructions mid-stream during HTTP payload transit. Validates that the gateway catches socket hangups cleanly, returning HTTP 502 Bad Gateway (`CRYPTO_SERVICE_UNREACHABLE`), and strictly rejects truncated or partially-transmitted JSON bodies.
- **Distributed Post-Commit Anchoring Ambiguity & Automated Self-Healing**: Simulates the classic distributed systems failure where an on-chain Fabric transaction commits successfully (status `active`), but an in-flight network timeout drops the response before reaching the gateway, causing local SQLite to record `anchor_failed`. Proves that `reconcileLedger()` discovers the discrepancy, auto-heals the local database record to `anchored`, and enables immediate downstream verification.
- **Slowloris Partial HTTP Connection Exhaustion Defense**: Opens raw TCP sockets streaming partial HTTP request lines byte-by-byte. Verifies that `server.setTimeout` and `configureServerTimeouts` actively destroy lingering half-open sockets within configured limits, preventing thread pool exhaustion.
- **Vault KMS Network Partition Fault Recovery**: Validates that when HashiCorp Vault is unreachable, `kms.get_keys()` fails loudly with structured exceptions rather than silently falling back to stale or cached key material, and `/rotate` returns HTTP 500 (`ROTATION_FAILED`) without destabilizing the microservice daemon.

```bash
# Run chaos and fault injection tests
cd components/verification-api && node --test tests/chaos_faults.test.js
```

---

### 11. Load, Resource Exhaustion & DoS Posture (`load_dos.test.js`, `test_load_dos.py`) (§6)
Validates system defenses against volumetric exhaustion, oversized payloads, rate limiter evasion, and memory leaks:
- **Oversized Payload Enforcement**:
  - **Verification API (Express)**: Configures explicit `express.json({ limit: '100kb' })` and central error middleware. Asserts that payloads > 100kb sent to `/verify`, `/issue`, or `/revoke` are immediately rejected with HTTP 413 (`PAYLOAD_TOO_LARGE`).
  - **Crypto Microservice (Flask)**: Enforces `app.config['MAX_CONTENT_LENGTH'] = 1MB` and `@app.errorhandler(413)`. Multi-megabyte requests to `/sign_hash` or `/verify_hash` are aborted with HTTP 413 before memory allocation.
- **Decompression Bomb Defense**: Sends small gzip-compressed payloads (~400 bytes) that decompress to > 100kb. Verifies that the JSON streaming parser aborts decompression upon reaching the limit and returns HTTP 413, preventing zip-bomb memory exhaustion.
- **Malformed Content-Encoding & Corrupted Streams**: Evaluates corrupted gzip byte streams and unsupported compression types (`Content-Encoding: unsupported`). Verifies clean HTTP 400 (`INVALID_JSON`) and 415 (`UNSUPPORTED_ENCODING`) responses without microservice instability.
- **Rate Limiter Enforcement & Evasion Resistance**:
  - Validates that unauthenticated `/verify` enforces request limits and returns HTTP 429 (`RATE_LIMITED`) with a standard `Retry-After` header.
  - Proves that spoofed/rotating `X-Forwarded-For` and `Client-IP` headers CANNOT bypass the IP-based rate limiter when `trust proxy` is disabled (`trustProxy: false`).
  - Validates that when `trust proxy` is explicitly configured for reverse proxy environments, client IPs are correctly segregated.
- **Sustained Burst Load & RSS Memory Stability**:
  - Hammers `/sign_hash` and `/verify_hash` with 150 consecutive C sign/verify cycles and 15 concurrent threads. Monitors process RSS memory via `resource.getrusage`, confirming memory growth is strictly bounded and verifying that `instance.free()` and `zeroize()` deallocations hold under sustained load.
  - Hammers unauthenticated `/verify` with 150 concurrent requests. Confirms 100% completion with 200 OK and bounded heap growth.

```bash
# Run verification gateway load & DoS tests
cd components/verification-api && node --test tests/load_dos.test.js

# Run crypto microservice load & DoS tests
cd components/crypto/crypto-service && pytest test_load_dos.py
```

---

### 12. Unified Local Test Runner (`run_all_unit_tests.sh`)
Orchestrates discovery and execution of all decoupled component test suites across the repository in a single command:

1. **Crypto Microservice**: Python interface, KMS zeroization, ML-DSA-65 signatures, auth truth tables, in-flight key rotation races, fuzz invariants, Vault chaos tests, and load/DoS RSS memory profiling (33 tests).
2. **Blockchain Chaincode**: Fabric mock contract unit, truth-table, concurrent execution, and monotonic revocation invariant suites running under Go `-race` detector (19 tests).
3. **Verification Gateway API**: Node.js native test runner (`node --test` across 67 unit, boundary, race, fast-check property invariant, chaos fault, and load/DoS tests).
4. **TypeScript SDK**: Jest test suite (6 tests covering client, revocation keys, and history queries).
5. **RFC 8785 Canonicalization Fuzzer**: 5,000-iteration cross-engine generative fuzz suite.
6. **Post-Quantum Tamper Sensitivity**: 26,472-bit exhaustive signature and commitment mutation suite.
7. **Differential Verifiers**: Automated cross-language differential testing suite (6 vectors).
8. **Offline Verifiers**: Parity test stages covering Node.js and Python offline tools.
9. **Authorization Mutation Testing**: 14-mutant multi-layer fault injection suite.
10. **Boundary & Edge-Case Mathematical Verification**: NIST CAVP vectors, container off-by-ones, and salt edge cases (15 tests).
11. **Native Go Coverage Fuzzing**: 16-worker coverage-guided fuzzing on chaincode entrypoints.

```bash
# Execute all decoupled unit and hardening suites across the repository
bash tests/run_all_unit_tests.sh
```

---

## 3. Coverage Summary

| Component / Track | Test Suite | Framework / Tooling | Scope / Test Count |
| :--- | :--- | :--- | :--- |
| **Crypto Microservice** | `components/crypto/crypto-service/test_*` | Python `unittest` / `liboqs` | 33 passed (includes vault chaos, load/DoS & RSS profiling) |
| **Blockchain Chaincode** | `components/blockchain/chaincode/src/*_test.go` | Go `testing` (`-race`) / `shimtest` | 19 passed (zero data races detected) |
| **Verification Gateway** | `components/verification-api/tests/*` | Node.js Test Runner (`node --test`) | 67 passed (includes chaos, slowloris, load, DoS & rate limiting) |
| **TypeScript SDK** | `sdk/test/index.test.ts` | Jest | 6 passed |
| **Canonicalization Fuzzer** | `tests/fuzz_canonicalize_parity.py` | Python + Node.js Bridge | 5,000 fuzz runs (7 test methods) passed |
| **Tamper Sensitivity** | `tests/test_tamper_sensitivity.py` | Python `unittest` / `liboqs` | 26,472 signature bit flips passed |
| **Differential Verifiers** | `tests/differential_offline_verifier.test.sh` | Bash / Python / Node | 6 differential vectors passed |
| **Offline Parity** | `tests/offline_verify_parity.test.sh` | Bash / Python / Node | 6 stages passed |
| **Mutation Testing** | `tests/mutation_auth.test.sh` | Bash / Go / Node / Python | 14/14 mutants killed (100% kill rate) |
| **Boundary Math Verification** | `tests/test_boundary_math.py` | Python `unittest` / Node.js Bridge | 15 passed (NIST CAVP SHA3-256, ML-DSA container off-by-one, 1MB salts) |
| **Native Coverage Fuzzing** | `scatterproof_fuzz_test.go` | Go `testing` (`go test -fuzz`) | 35,000+ executions / 16 workers (Anchor & Revoke fuzz targets) |
