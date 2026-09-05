process.env.NODE_ENV = 'test';
process.env.SQLITE_DB_PATH = ':memory:';
process.env.VERIFICATION_API_KEY = 'test-auth-key-chaos';
process.env.REVOKE_API_KEY = 'test-revoke-key-chaos';
process.env.CRYPTO_SERVICE_API_KEY = 'test-crypto-key-chaos';

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { randomUUID, createHash } from 'node:crypto';

const { app, configureServerTimeouts } = await import('../src/server.js');
const { verifyRoute } = await import('../src/routes/verify.js');
const { issueRoute } = await import('../src/routes/issue.js');
const { createCredential, getCredentialById, clearDatabase } = await import('../src/db/models.js');
const { setContractInstance } = await import('../src/chain/fabric.js');
const { reconcileLedger } = await import('../src/reconcile.js');

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

test('Chaos: Upstream Crypto Service Full Timeout on /verify returns 504 (§5)', async () => {
  clearDatabase();
  const credentialId = randomUUID();
  const dataHash = createHash('sha3-256').update('timeout-test').digest('hex');

  await createCredential({
    id: credentialId,
    dataHash,
    algorithm: 'ML-DSA-65',
    signature: '3045022100timeout1234',
    publicKeyId: 'timeout-pub-key-id',
    anchorTxId: 'tx-timeout-1',
    status: 'anchored',
    issuedAt: new Date().toISOString(),
    idempotencyKey: 'idemp-timeout-1'
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

  // Start mock server that hangs forever (never sends response)
  const hangingServer = http.createServer((req, res) => {
    // Intentionally never respond, hold request open
  });

  await new Promise((resolve) => hangingServer.listen(0, '127.0.0.1', resolve));
  const hangingPort = hangingServer.address().port;

  const originalCryptoUrl = process.env.CRYPTO_SERVICE_URL;
  const originalTimeout = process.env.CRYPTO_SERVICE_TIMEOUT_MS;

  process.env.CRYPTO_SERVICE_URL = `http://127.0.0.1:${hangingPort}`;
  process.env.CRYPTO_SERVICE_TIMEOUT_MS = '150'; // 150ms timeout

  try {
    const startTime = Date.now();
    const mockRes = createMockResponse();

    await verifyRoute({ body: { credentialId, dataHash } }, mockRes);
    const elapsed = Date.now() - startTime;

    // Must fail fast within timeout window
    assert.ok(elapsed < 1000, `Request took ${elapsed}ms, expected timeout within ~150ms`);
    assert.equal(mockRes.statusCode, 504, 'Must return HTTP 504 Gateway Timeout');
    assert.equal(mockRes.body.code, 'CRYPTO_SERVICE_TIMEOUT');
    assert.ok(mockRes.body.error.includes('timed out'));
  } finally {
    process.env.CRYPTO_SERVICE_URL = originalCryptoUrl;
    process.env.CRYPTO_SERVICE_TIMEOUT_MS = originalTimeout;
    await new Promise((resolve) => hangingServer.close(resolve));
  }
});

test('Chaos: Upstream Crypto Service Timeout on /issue returns 504 (§5)', async () => {
  clearDatabase();
  const dataHash = createHash('sha3-256').update('issue-timeout-test').digest('hex');

  const hangingServer = http.createServer((req, res) => {
    // Intentionally never respond
  });

  await new Promise((resolve) => hangingServer.listen(0, '127.0.0.1', resolve));
  const hangingPort = hangingServer.address().port;

  const originalCryptoUrl = process.env.CRYPTO_SERVICE_URL;
  const originalTimeout = process.env.CRYPTO_SERVICE_TIMEOUT_MS;

  process.env.CRYPTO_SERVICE_URL = `http://127.0.0.1:${hangingPort}`;
  process.env.CRYPTO_SERVICE_TIMEOUT_MS = '150';

  try {
    const startTime = Date.now();
    const mockRes = createMockResponse();

    await issueRoute({ body: { dataHash } }, mockRes);
    const elapsed = Date.now() - startTime;

    assert.ok(elapsed < 1000, `Issue request took ${elapsed}ms, expected timeout within ~150ms`);
    assert.equal(mockRes.statusCode, 504, 'Must return HTTP 504 on signing service timeout');
    assert.equal(mockRes.body.code, 'CRYPTO_SERVICE_TIMEOUT');
  } finally {
    process.env.CRYPTO_SERVICE_URL = originalCryptoUrl;
    process.env.CRYPTO_SERVICE_TIMEOUT_MS = originalTimeout;
    await new Promise((resolve) => hangingServer.close(resolve));
  }
});

test('Chaos: Upstream TCP Connection Reset Mid-Response returns 502 (§5)', async () => {
  clearDatabase();
  const credentialId = randomUUID();
  const dataHash = createHash('sha3-256').update('reset-test').digest('hex');

  await createCredential({
    id: credentialId,
    dataHash,
    algorithm: 'ML-DSA-65',
    signature: '3045022100reset1234',
    publicKeyId: 'reset-pub-key-id',
    anchorTxId: 'tx-reset-1',
    status: 'anchored',
    issuedAt: new Date().toISOString(),
    idempotencyKey: 'idemp-reset-1'
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

  // Raw TCP server that writes partial HTTP header and immediately destroys the socket
  const resetServer = net.createServer((socket) => {
    socket.on('data', () => {
      // Send partial HTTP bytes and abruptly terminate connection (TCP RST)
      socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"val');
      socket.destroy();
    });
  });

  await new Promise((resolve) => resetServer.listen(0, '127.0.0.1', resolve));
  const resetPort = resetServer.address().port;

  const originalCryptoUrl = process.env.CRYPTO_SERVICE_URL;
  process.env.CRYPTO_SERVICE_URL = `http://127.0.0.1:${resetPort}`;

  try {
    const mockRes = createMockResponse();
    await verifyRoute({ body: { credentialId, dataHash } }, mockRes);

    // Invariant: Truncated JSON stream must NEVER be treated as valid or return 200
    assert.equal(mockRes.statusCode, 502, 'Connection reset must return HTTP 502 Bad Gateway');
    assert.equal(mockRes.body.code, 'CRYPTO_SERVICE_UNREACHABLE');
  } finally {
    process.env.CRYPTO_SERVICE_URL = originalCryptoUrl;
    await new Promise((resolve) => resetServer.close(resolve));
  }
});

test('Chaos: Distributed Anchoring Ambiguity (Timeout Post-Commit) & reconcileLedger Self-Healing (§5)', async () => {
  clearDatabase();
  const credentialId = randomUUID();
  const dataHash = createHash('sha3-256').update('distributed-ambiguity-test').digest('hex');

  // Ledger state: Transaction committed on blockchain, but network timeout occurred
  // before confirmation reached API gateway
  let ledgerCommitted = true;

  const mockContract = {
    async submitTransaction(fn, id, hash, issuer, ts) {
      if (fn === 'AnchorProof') {
        // Simulates transaction committing successfully on ledger,
        // but network timeout drops the response back to caller
        throw new Error('504 Gateway Timeout: Fabric orderer transaction commit response lost in transit');
      }
      throw new Error(`Unexpected function ${fn}`);
    },
    async evaluateTransaction(fn, id) {
      if (fn === 'QueryProof') {
        if (ledgerCommitted) {
          return new TextEncoder().encode(JSON.stringify({
            CredentialID: id,
            dataHash,
            Status: 'active',
            IssuerID: 'IssuerMSP'
          }));
        }
        throw new Error(`proof ${id} does not exist`);
      }
      throw new Error(`Unexpected query function ${fn}`);
    }
  };
  setContractInstance(mockContract);

  // Pre-seed local database with the credential marked 'anchor_failed'
  // (exact state produced when anchorProof throws network error)
  await createCredential({
    id: credentialId,
    dataHash,
    algorithm: 'ML-DSA-65',
    signature: '3045022100anchorambiguity',
    publicKeyId: 'chaos-key-id',
    anchorTxId: null,
    status: 'anchor_failed',
    issuedAt: new Date().toISOString(),
    idempotencyKey: `idemp-${credentialId}`
  });

  // Verify initial state is anchor_failed
  const preRecord = await getCredentialById(credentialId);
  assert.equal(preRecord.status, 'anchor_failed');

  // Execute reconciliation daemon
  const reconcileReport = await reconcileLedger();

  assert.equal(reconcileReport.mismatchCount, 1, 'Reconciliation must detect discrepancy between local anchor_failed and ledger active');
  assert.equal(reconcileReport.discrepancies[0].credentialId, credentialId);
  assert.equal(reconcileReport.discrepancies[0].localStatus, 'anchor_failed');
  assert.equal(reconcileReport.discrepancies[0].ledgerStatus, 'active');

  // Assert automated self-healing
  const postRecord = await getCredentialById(credentialId);
  assert.equal(postRecord.status, 'anchored', 'Reconciliation MUST automatically heal local state to anchored');

  // Now verify that subsequent verifyRoute call succeeds against self-healed state
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    json: async () => ({ valid: true })
  });

  try {
    const verifyRes = createMockResponse();
    await verifyRoute({ body: { credentialId, dataHash } }, verifyRes);

    assert.equal(verifyRes.statusCode, 200);
    assert.equal(verifyRes.body.valid, true, 'Credential must be fully valid after self-healing');
    assert.equal(verifyRes.body.anchorStatus, 'active');
  } finally {
    global.fetch = originalFetch;
  }
});

test('Chaos: Slowloris Partial HTTP Connection Exhaustion Defense (§5)', async () => {
  const server = http.createServer(app);
  configureServerTimeouts(server);
  server.setTimeout(250, (socket) => {
    socket.destroy();
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  let socket;

  try {
    socket = net.connect(port, '127.0.0.1');
    await new Promise((resolve) => socket.once('connect', resolve));

    // Send partial HTTP request line and incomplete headers
    socket.write('POST /verify HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slowloris: attack\r\n');

    let closed = false;
    const closePromise = new Promise((resolve) => {
      socket.on('close', () => {
        closed = true;
        resolve();
      });
      socket.on('error', () => {
        closed = true;
        resolve();
      });
    });

    // Wait for server to drop the connection
    await Promise.race([
      closePromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Slowloris socket hung open beyond timeout')), 1500))
    ]);

    assert.ok(closed, 'Slowloris partial connection must be dropped by the server');
  } finally {
    if (socket && !socket.destroyed) {
      socket.destroy();
    }
    await new Promise((resolve) => server.close(resolve));
  }
});
