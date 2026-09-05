#!/usr/bin/env bash
# ==============================================================================
# ScatterID — Unified Offline Unit Test Suite Runner
# ==============================================================================
# Executes all standalone unit and parity test suites across the repository
# without requiring Docker daemon or a live Fabric blockchain network:
#   1. Crypto Service Unit Tests (Python unittest / NIST ML-DSA-65 & KMS)
#   2. Blockchain Smart Contract Unit Tests (Go test / Fabric MockStub)
#   3. Verification API Unit Tests (Node.js Jest / Auth & In-Memory SQLite)
#   4. TypeScript SDK Unit Tests (Jest / Canonicalization & API client)
#   5. Offline Cryptographic Verifier Parity Suite (Node.js & Python)
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR="$( cd "$DIR/.." >/dev/null 2>&1 && pwd )"
cd "$ROOT_DIR"

BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
CYAN="\033[36m"
YELLOW="\033[33m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}======================================================================${RESET}"
echo -e "${BOLD}${CYAN}            ScatterID — Unified Local Unit Test Harness               ${RESET}"
echo -e "${BOLD}${CYAN}======================================================================${RESET}"

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

run_suite() {
  local suite_name="$1"
  local cmd="$2"
  TOTAL_SUITES=$((TOTAL_SUITES + 1))

  echo -e "\n${BOLD}>>> [${TOTAL_SUITES}] Running Suite: ${suite_name}${RESET}"
  if eval "$cmd"; then
    echo -e "${GREEN}✓ ${suite_name} PASSED${RESET}"
    PASSED_SUITES=$((PASSED_SUITES + 1))
  else
    echo -e "${RED}✕ ${suite_name} FAILED${RESET}"
    FAILED_SUITES=$((FAILED_SUITES + 1))
  fi
}

# Resolve Python environment
if command -v python3 >/dev/null 2>&1 && python3 -c "import oqs" >/dev/null 2>&1; then
  PY_BIN="python3"
elif [ -x "/tmp/crypto_venv/bin/python3" ]; then
  PY_BIN="/tmp/crypto_venv/bin/python3"
else
  PY_BIN="python3"
fi

# 1. Crypto Service Tests
if [ -d "components/crypto/crypto-service" ]; then
  run_suite "Crypto Microservice (Python / ML-DSA-65 & KMS)" \
    "$PY_BIN -m unittest discover components/crypto/crypto-service"
fi

# 2. Blockchain Smart Contract Chaincode Tests (with Go Race Detector)
if [ -f "components/blockchain/chaincode/src/scatterproof_test.go" ] && command -v go >/dev/null 2>&1; then
  run_suite "Blockchain Chaincode (Go -race / MockStub)" \
    "(cd components/blockchain/chaincode/src && go test -race -v ./...)"
else
  echo -e "\n${YELLOW}[!] Skipping Blockchain Chaincode tests (scatterproof_test.go not on current branch or Go unavailable)${RESET}"
fi

# 3. Verification API Unit Tests
if [ -d "components/verification-api/tests" ] && command -v npm >/dev/null 2>&1; then
  run_suite "Verification API (Node.js / Express & SQLite)" \
    "(cd components/verification-api && npm test)"
else
  echo -e "\n${YELLOW}[!] Skipping Verification API tests (components/verification-api/tests not on current branch)${RESET}"
fi

# 4. TypeScript SDK Unit Tests
if [ -d "sdk/test" ] && command -v npm >/dev/null 2>&1; then
  run_suite "TypeScript SDK (Jest / Client & Canonicalization)" \
    "(cd sdk && npm test)"
fi

# 5. Canonicalization Parity Generative Fuzzer
if [ -f "tests/fuzz_canonicalize_parity.py" ] && command -v python3 >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
  run_suite "RFC 8785 Canonicalization Parity Fuzzer (5,000 Iterations)" \
    "$PY_BIN tests/fuzz_canonicalize_parity.py"
fi

# 6. Cryptographic Tamper Sensitivity & Invariant Suite
if [ -f "tests/test_tamper_sensitivity.py" ] && command -v python3 >/dev/null 2>&1; then
  run_suite "Cryptographic Tamper Sensitivity (26,472 Bit Flips)" \
    "$PY_BIN tests/test_tamper_sensitivity.py"
fi

# 7. Cross-Implementation Differential Verifier Suite
if [ -f "tests/differential_offline_verifier.test.sh" ]; then
  run_suite "Differential Offline Verifiers (Python vs Node.js)" \
    "bash tests/differential_offline_verifier.test.sh"
fi

# 8. Offline Verifier Cross-Language Parity Tests
if [ -f "tests/offline_verify_parity.test.sh" ]; then
  run_suite "Offline Verifiers Cross-Language Parity (Node.js & Python)" \
    "bash tests/offline_verify_parity.test.sh"
fi

# 9. Authorization Mutation Testing Framework (§9)
if [ -f "tests/mutation_auth.test.sh" ]; then
  run_suite "Authorization Mutation Testing (14 Mutants / Chaincode, Gateway & Crypto)" \
    "bash tests/mutation_auth.test.sh"
fi

# 10. Boundary & Edge-Case Mathematical Verification (§3)
if [ -f "tests/test_boundary_math.py" ] && command -v python3 >/dev/null 2>&1; then
  run_suite "Boundary & Edge-Case Mathematical Verification (NIST CAVP, Off-by-One, Salt Boundaries)" \
    "$PY_BIN tests/test_boundary_math.py"
fi

# 11. Native Go Coverage-Guided Fuzzing (§1)
if [ -f "components/blockchain/chaincode/src/scatterproof_fuzz_test.go" ] && command -v go >/dev/null 2>&1; then
  run_suite "Native Go Coverage Fuzzing (go test -fuzz / Anchor & Revoke Invariants)" \
    "(cd components/blockchain/chaincode/src && go test -fuzz=FuzzAnchorProof -fuzztime=2s && go test -fuzz=FuzzRevokeProof -fuzztime=2s)"
fi

# Summary
echo -e "\n${BOLD}${CYAN}======================================================================${RESET}"
echo -e "${BOLD}Summary: ${PASSED_SUITES}/${TOTAL_SUITES} test suites passed.${RESET}"
if [ $FAILED_SUITES -eq 0 ]; then
  echo -e "${BOLD}${GREEN}ALL EXECUTED SUITES PASSED!${RESET}"
  echo -e "${BOLD}${CYAN}======================================================================${RESET}"
  exit 0
else
  echo -e "${BOLD}${RED}${FAILED_SUITES} test suite(s) failed.${RESET}"
  echo -e "${BOLD}${CYAN}======================================================================${RESET}"
  exit 1
fi
