process.env.NODE_ENV = 'test';
process.env.SQLITE_DB_PATH = ':memory:';
process.env.VERIFICATION_API_KEY = 'test-auth-key-fuzz';
process.env.REVOKE_API_KEY = 'test-revoke-key-fuzz';
process.env.CRYPTO_SERVICE_API_KEY = 'test-crypto-key-fuzz';

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import fc from 'fast-check';

const { verifyRoute } = await import('../src/routes/verify.js');
const { revokeRoute } = await import('../src/routes/revoke.js');
const { statusRoute } = await import('../src/routes/status.js');
const { retryAnchorRoute } = await import('../src/routes/issue.js');
const { createCredential, getCredentialById, clearDatabase } = await import('../src/db/models.js');
const { setContractInstance } = await import('../src/chain/fabric.js');
const { canonicalize } = await import('../../../tools/verify_offline.js');

function createMockResponse() {
  const res = {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    }
  };
  return res;
}

test('Property: Monotonic Revocation State Machine Invariant (§2 & §4)', async () => {
  const TRIALS = 25;
  const OPS_PER_TRIAL = 20;

  for (let trial = 0; trial < TRIALS; trial++) {
    clearDatabase();
    const credentialId = randomUUID();
    const dataHash = createHash('sha3-256').update(`trial-${trial}-${credentialId}`).digest('hex');

    let ledgerStatus = 'active';

    const mockContract = {
      async submitTransaction(fn, id, issuer) {
        if (fn === 'RevokeProof') {
          if (ledgerStatus === 'revoked') {
            throw new Error(`proof ${id} is already revoked`);
          }
          ledgerStatus = 'revoked';
          return new TextEncoder().encode(JSON.stringify({ status: 'revoked', credentialId: id }));
        }
        if (fn === 'AnchorProof') {
          if (ledgerStatus !== 'unanchored') {
            throw new Error(`the proof for credential ${id} already exists`);
          }
          ledgerStatus = 'active';
          return new TextEncoder().encode(JSON.stringify({ status: 'active', credentialId: id }));
        }
        throw new Error(`Unsupported function ${fn}`);
      },
      async evaluateTransaction(fn, id) {
        if (fn === 'QueryProof') {
          return new TextEncoder().encode(JSON.stringify({
            CredentialID: id,
            dataHash,
            Status: ledgerStatus,
            IssuerID: 'IssuerMSP'
          }));
        }
        throw new Error(`Unsupported query function ${fn}`);
      }
    };

    setContractInstance(mockContract);

    // Seed initial active anchored credential
    await createCredential({
      id: credentialId,
      dataHash,
      algorithm: 'ML-DSA-65',
      signature: '3045022100deadbeefcafe',
      publicKeyId: `key-id-${trial}`,
      anchorTxId: `tx-anchor-${trial}`,
      status: 'anchored',
      issuedAt: new Date().toISOString(),
      idempotencyKey: `idemp-trial-${trial}`
    });

    const originalFetch = global.fetch;
    global.fetch = async (url) => {
      if (url.includes('verify_hash') || url.includes('5001')) {
        return {
          ok: true,
          json: async () => ({ valid: true })
        };
      }
      return { ok: true, json: async () => ({}) };
    };

    try {
      let isRevoked = false;

      for (let op = 0; op < OPS_PER_TRIAL; op++) {
        const opType = Math.floor(Math.random() * 4);

        if (opType === 0) {
          // Verify
          const res = createMockResponse();
          await verifyRoute({ body: { credentialId, dataHash } }, res);

          assert.equal(res.statusCode, 200);
          if (isRevoked) {
            assert.equal(res.body.valid, false, 'Revoked credential MUST NOT be valid');
            assert.equal(res.body.anchorStatus, 'revoked');
          } else {
            assert.equal(res.body.valid, true);
            assert.equal(res.body.anchorStatus, 'active');
          }
        } else if (opType === 1) {
          // Revoke
          const res = createMockResponse();
          await revokeRoute({ body: { credentialId }, callerTier: 'revoke_api_key' }, res);

          assert.equal(res.statusCode, 200);
          assert.equal(res.body.status, 'revoked');
          isRevoked = true;
        } else if (opType === 2) {
          // Status
          const res = createMockResponse();
          await statusRoute({ params: { id: credentialId } }, res);

          assert.equal(res.statusCode, 200);
          if (isRevoked) {
            assert.equal(res.body.status, 'revoked');
          }
        } else if (opType === 3) {
          // Retry anchor (attempt resurrection)
          const res = createMockResponse();
          await retryAnchorRoute({ params: { credentialId } }, res);

          // Retry anchor should never reactivate a revoked proof
          const currentRecord = await getCredentialById(credentialId);
          if (isRevoked) {
            assert.equal(currentRecord.status, 'revoked', 'Retry anchor must NEVER resurrect a revoked credential');
          }
        }

        // Global Invariant Verification at every step:
        const checkRecord = await getCredentialById(credentialId);
        if (isRevoked) {
          assert.equal(checkRecord.status, 'revoked',
            `INVARIANT VIOLATION: Credential ${credentialId} reverted from revoked to ${checkRecord.status} at op ${op}!`);
        }
      }
    } finally {
      global.fetch = originalFetch;
    }
  }
});

test('Property: Deterministic Pure Verification Function with Zero Side-Effects (§2)', async () => {
  clearDatabase();
  const credentialId = randomUUID();
  const dataHash = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

  await createCredential({
    id: credentialId,
    dataHash,
    algorithm: 'ML-DSA-65',
    signature: '3045022100beef123456',
    publicKeyId: 'pure-key-id',
    anchorTxId: 'tx-pure-1',
    status: 'anchored',
    issuedAt: new Date().toISOString(),
    idempotencyKey: 'idemp-pure-1'
  });

  const mockContract = {
    async evaluateTransaction(fn, id) {
      return new TextEncoder().encode(JSON.stringify({
        CredentialID: id,
        dataHash,
        Status: 'active',
        IssuerID: 'IssuerMSP'
      }));
    }
  };
  setContractInstance(mockContract);

  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    json: async () => ({ valid: true })
  });

  try {
    const baselineRes = createMockResponse();
    await verifyRoute({ body: { credentialId, dataHash } }, baselineRes);
    const expectedStatus = baselineRes.statusCode;
    const expectedBody = JSON.stringify(baselineRes.body);

    // Execute 50 parallel verification queries
    const parallelRuns = Array.from({ length: 50 }, async () => {
      const res = createMockResponse();
      await verifyRoute({ body: { credentialId, dataHash } }, res);
      assert.equal(res.statusCode, expectedStatus, 'Verify status code must be deterministic');
      assert.equal(JSON.stringify(res.body), expectedBody, 'Verify response body must be bit-for-bit identical');
    });

    await Promise.all(parallelRuns);

    // Verify DB integrity: zero side-effects
    const record = await getCredentialById(credentialId);
    assert.equal(record.status, 'anchored');
    assert.equal(record.dataHash, dataHash);
  } finally {
    global.fetch = originalFetch;
  }
});

test('Property (fast-check): Generative Adversarial Fuzzing on /verify HTTP Endpoint (§1)', async () => {
  clearDatabase();
  const legitimateId = randomUUID();
  const legitimateHash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  await createCredential({
    id: legitimateId,
    dataHash: legitimateHash,
    algorithm: 'ML-DSA-65',
    signature: '3045022100beef123456',
    publicKeyId: 'fuzz-key-id',
    anchorTxId: 'tx-fuzz-1',
    status: 'anchored',
    issuedAt: new Date().toISOString(),
    idempotencyKey: 'idemp-fuzz-1'
  });

  // Generative input fuzzing: generate 300 arbitrary inputs
  await fc.assert(
    fc.asyncProperty(
      fc.record({
        dataHash: fc.oneof(
          fc.string(),
          fc.stringMatching(/^[0-9a-f]{0,100}$/),
          fc.constant(''),
          fc.constant(null),
          fc.constant(undefined),
          fc.constant("' OR 1=1; --"),
          fc.constant("'; DROP TABLE credentials; --"),
          fc.constant("\x00\x01\x02\x03\xff"),
          fc.constant("A".repeat(10000))
        ),
        credentialId: fc.oneof(
          fc.string(),
          fc.uuid(),
          fc.constant(''),
          fc.constant(null),
          fc.constant(undefined),
          fc.constant("' UNION SELECT 1,2,3,4,5,6,7,8,9; --"),
          fc.constant("../../../../etc/passwd"),
          fc.constant("..\..\windows\system32"),
          fc.constant("\x00\x00\x00")
        ),
        extraField: fc.oneof(
          fc.string(),
          fc.integer(),
          fc.dictionary(fc.string(), fc.string()),
          fc.array(fc.string())
        )
      }),
      async (payload) => {
        const res = createMockResponse();

        // Must never throw unhandled exception or crash
        await verifyRoute({ body: payload }, res);

        // Rejection must be clean: 400 Bad Request or 404 Not Found (or 200 if legitimate accidentally matched)
        assert.ok([200, 400, 404, 502].includes(res.statusCode),
          `HTTP status ${res.statusCode} unexpected for payload: ${JSON.stringify(payload)}`);

        // If 400, body must contain structured error
        if (res.statusCode === 400) {
          assert.ok(res.body && res.body.error, '400 response must have error message');
          assert.equal(res.body.code, 'INVALID_PARAMETER');
        }

        // Database must remain healthy and queryable
        const check = await getCredentialById(legitimateId);
        assert.ok(check, 'Database must not be corrupted by SQL injection or malformed payload');
      }
    ),
    { numRuns: 300 }
  );
});

test('Property (fast-check): Generative Adversarial Fuzzing on /revoke Endpoint (§1)', async () => {
  clearDatabase();
  const legitimateId = randomUUID();

  await createCredential({
    id: legitimateId,
    dataHash: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
    algorithm: 'ML-DSA-65',
    signature: '3045022100beef123456',
    publicKeyId: 'revoke-fuzz-key',
    anchorTxId: 'tx-fuzz-revoke',
    status: 'anchored',
    issuedAt: new Date().toISOString(),
    idempotencyKey: 'idemp-fuzz-revoke'
  });

  await fc.assert(
    fc.asyncProperty(
      fc.record({
        credentialId: fc.oneof(
          fc.string(),
          fc.constant(''),
          fc.constant(null),
          fc.constant(undefined),
          fc.constant("' OR '1'='1"),
          fc.constant("'; DROP TABLE credentials; --"),
          fc.constant("../../../shadow"),
          fc.constant("00000000-0000-0000-0000-000000000000") // v0 not v4
        )
      }),
      async (payload) => {
        const res = createMockResponse();

        await revokeRoute({ body: payload, callerTier: 'revoke_api_key' }, res);

        assert.ok([200, 400, 404, 502].includes(res.statusCode),
          `HTTP status ${res.statusCode} unexpected for revoke payload: ${JSON.stringify(payload)}`);

        if (res.statusCode === 400) {
          assert.equal(res.body.code, 'INVALID_PARAMETER');
        }

        const check = await getCredentialById(legitimateId);
        assert.ok(check, 'Credentials table must remain intact');
      }
    ),
    { numRuns: 200 }
  );
});

test('Property (fast-check): RFC 8785 JSON Canonicalization Parity & Determinism Invariant (§2)', async () => {
  await fc.assert(
    fc.property(
      fc.jsonValue({ maxDepth: 5 }),
      (val) => {
        try {
          const canon1 = canonicalize(val);
          const canon2 = canonicalize(val);

          // Determinism invariant
          assert.equal(canon1, canon2, 'Canonicalization must be pure deterministic');

          // Hash determinism invariant
          if (canon1 !== undefined) {
            const h1 = createHash('sha3-256').update(canon1, 'utf8').digest('hex');
            const h2 = createHash('sha3-256').update(canon2, 'utf8').digest('hex');
            assert.equal(h1, h2, 'Hash of canonical output must be identical');

            // If it is a top-level flat object with multiple keys, verify UTF-16 code unit ordering directly from JSON string
            if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
              const keys = Object.keys(val);
              if (keys.length > 1 && keys.every(k => typeof val[k] !== 'object')) {
                const outKeys = [...canon1.matchAll(/"((?:\\.|[^"\\])*)":/g)].map(m => JSON.parse(`"${m[1]}"`));
                for (let i = 0; i < outKeys.length - 1; i++) {
                  assert.ok(outKeys[i] <= outKeys[i + 1],
                    `Keys not sorted in canonical output: ${outKeys[i]} > ${outKeys[i + 1]}`);
                }
              }
            }
          }
        } catch (err) {
          // Expected rejections: fast-check might produce NaN or Infinity
          assert.ok(
            err.message.includes('NaN') ||
            err.message.includes('Infinity') ||
            err.message.includes('circular') ||
            err.message.includes('Maximum call stack'),
            `Unexpected error during canonicalization: ${err.message}`
          );
        }
      }
    ),
    { numRuns: 500 }
  );
});
