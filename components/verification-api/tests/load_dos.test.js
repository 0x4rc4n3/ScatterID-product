import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';

process.env.NODE_ENV = 'test';
process.env.SQLITE_DB_PATH = ':memory:';
process.env.VERIFICATION_API_KEY = 'test-auth-key-load';
process.env.REVOKE_API_KEY = 'test-revoke-key-load';
process.env.CRYPTO_SERVICE_API_KEY = 'test-crypto-key-load';

const { createApp, configureServerTimeouts } = await import('../src/server.js');
const { createCredential } = await import('../src/db/models.js');
const { setContractInstance } = await import('../src/chain/fabric.js');

const TEST_KEY = 'test-auth-key-load';
const TEST_REVOKE_KEY = 'test-revoke-key-load';

test('Load & DoS: Oversized payload (> 100kb) rejected with HTTP 413 (§6)', async () => {
  const app = createApp({ bodyLimit: '100kb' });
  const server = http.createServer(app);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    // Construct 150KB payload
    const largePadding = 'x'.repeat(150 * 1024);
    const oversizedBody = JSON.stringify({
      dataHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      signature: 'aabbcc',
      publicKeyId: '0123456789abcdef0123456789abcdef',
      padding: largePadding
    });

    // 1. POST /verify
    const verifyRes = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: oversizedBody
    });
    assert.equal(verifyRes.status, 413, '/verify must reject oversized payload with 413');
    const verifyJson = await verifyRes.json();
    assert.equal(verifyJson.code, 'PAYLOAD_TOO_LARGE');

    // 2. POST /issue
    const issueRes = await fetch(`http://127.0.0.1:${port}/issue`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TEST_KEY}`,
        'Content-Type': 'application/json'
      },
      body: oversizedBody
    });
    assert.equal(issueRes.status, 413, '/issue must reject oversized payload with 413');
    const issueJson = await issueRes.json();
    assert.equal(issueJson.code, 'PAYLOAD_TOO_LARGE');

    // 3. POST /revoke
    const revokeRes = await fetch(`http://127.0.0.1:${port}/revoke`, {
      method: 'POST',
      headers: {
        'X-Revoke-Key': TEST_REVOKE_KEY,
        'Content-Type': 'application/json'
      },
      body: oversizedBody
    });
    assert.equal(revokeRes.status, 413, '/revoke must reject oversized payload with 413');
    const revokeJson = await revokeRes.json();
    assert.equal(revokeJson.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('Load & DoS: Decompression bomb defense aborts expanded stream with 413 (§6)', async () => {
  const app = createApp({ bodyLimit: '100kb' });
  const server = http.createServer(app);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    // Create 300KB uncompressed JSON payload
    const uncompressedData = JSON.stringify({
      dataHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      padding: '0'.repeat(300 * 1024)
    });
    // Compress with gzip: shrinks to ~400 bytes, far below the 100kb transport limit
    const compressedGzip = zlib.gzipSync(Buffer.from(uncompressedData, 'utf8'));
    assert.ok(compressedGzip.length < 2048, 'Compressed payload must be small');

    // Send compressed bomb to /verify
    const res = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip'
      },
      body: compressedGzip
    });

    assert.equal(res.status, 413, 'Decompression bomb expanding past limit must return 413');
    const body = await res.json();
    assert.equal(body.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('Load & DoS: Malformed Content-Encoding & corrupted JSON payloads (§6)', async () => {
  const app = createApp({ bodyLimit: '100kb' });
  const server = http.createServer(app);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    // 1. Corrupted gzip stream
    const corruptedStream = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff, 0xff, 0xee]);
    const corruptRes = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip'
      },
      body: corruptedStream
    });
    assert.equal(corruptRes.status, 400, 'Corrupted gzip stream must return 400 Bad Request');

    // 2. Unsupported Content-Encoding
    const unsupportedRes = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Encoding': 'unsupported-compression-type'
      },
      body: Buffer.from('{}')
    });
    assert.equal(unsupportedRes.status, 415, 'Unsupported encoding must return 415');
    const unsuppJson = await unsupportedRes.json();
    assert.equal(unsuppJson.code, 'UNSUPPORTED_ENCODING');

    // 3. Malformed JSON syntax
    const malformedRes = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"dataHash": "unclosed-string'
    });
    assert.equal(malformedRes.status, 400, 'Malformed JSON must return 400');
    const malfJson = await malformedRes.json();
    assert.equal(malfJson.code, 'INVALID_JSON');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('Load & DoS: Rate limiter enforcement on unauthenticated /verify returns HTTP 429 (§6)', async () => {
  const app = createApp({ rateLimitMax: 5 });
  const server = http.createServer(app);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    // First 5 requests should be accepted by rate limiter (returns 400 on empty body, not 429)
    for (let i = 0; i < 5; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      assert.notEqual(res.status, 429, `Request ${i + 1} should not be rate limited`);
    }

    // 6th request must trigger rate limiter
    const rateLimitedRes = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.equal(rateLimitedRes.status, 429, '6th request must return 429 Too Many Requests');
    const body = await rateLimitedRes.json();
    assert.equal(body.code, 'RATE_LIMITED');
    assert.ok(rateLimitedRes.headers.get('retry-after'), 'Must supply Retry-After header');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('Load & DoS: Rate limiter bypass evasion resistance against spoofed X-Forwarded-For (§6)', async () => {
  // By default, trust proxy is false. Spoofed X-Forwarded-For headers MUST NOT reset or evade rate limit.
  const app = createApp({ rateLimitMax: 5, trustProxy: false });
  const server = http.createServer(app);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    const spoofedIps = [
      '203.0.113.10',
      '198.51.100.22',
      '192.0.2.33',
      '10.10.10.44',
      '172.16.50.55'
    ];

    // Fire 5 requests, each with a different forged X-Forwarded-For header
    for (let i = 0; i < 5; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': spoofedIps[i],
          'Client-IP': spoofedIps[i]
        },
        body: JSON.stringify({})
      });
      assert.notEqual(res.status, 429, `Request ${i + 1} should consume quota`);
    }

    // 6th request with a new spoofed IP must still be blocked by socket IP rate limit
    const evasionAttemptRes = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '8.8.8.8',
        'Client-IP': '8.8.8.8'
      },
      body: JSON.stringify({})
    });

    assert.equal(
      evasionAttemptRes.status,
      429,
      'Spoofed X-Forwarded-For must NOT bypass rate limiter when trust proxy is disabled'
    );
    const body = await evasionAttemptRes.json();
    assert.equal(body.code, 'RATE_LIMITED');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('Load & DoS: Trusted proxy correctly segregates client IPs behind reverse proxy (§6)', async () => {
  // When trust proxy is explicitly enabled (e.g. behind Nginx or Docker ingress)
  const app = createApp({ rateLimitMax: 3, trustProxy: true });
  const server = http.createServer(app);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    // Client A sends 3 requests
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': '198.51.100.101'
        },
        body: JSON.stringify({})
      });
      assert.notEqual(res.status, 429, `Client A request ${i + 1} accepted`);
    }

    // Client A 4th request is rate limited
    const clientALimited = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.101'
      },
      body: JSON.stringify({})
    });
    assert.equal(clientALimited.status, 429, 'Client A must be rate limited');

    // Distinct Client B sending from different IP is NOT rate limited by Client A's quota
    const clientBRes = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.202'
      },
      body: JSON.stringify({})
    });
    assert.notEqual(clientBRes.status, 429, 'Client B should not be blocked by Client A quota');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('Load & DoS: Sustained burst load and memory stability on unauthenticated /verify (§6)', async () => {
  // Mock crypto upstream for verify endpoint
  const mockCrypto = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ valid: true }));
  });
  await new Promise(r => mockCrypto.listen(0, '127.0.0.1', r));
  const cryptoPort = mockCrypto.address().port;
  process.env.CRYPTO_SERVICE_URL = `http://127.0.0.1:${cryptoPort}`;

  const app = createApp({ rateLimitMax: 10000 });
  const server = configureServerTimeouts(http.createServer(app));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const validHash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const testId = '44444444-4444-4444-8444-444444444444';

  createCredential({
    id: testId,
    dataHash: validHash,
    algorithm: 'ML-DSA-65',
    signature: 'abcd',
    publicKeyId: '12345678901234567890123456789012',
    anchorTxId: 'tx-burst',
    status: 'anchored',
    issuedAt: new Date().toISOString()
  });

  const mockContract = {
    async evaluateTransaction(fn, id) {
      return new TextEncoder().encode(JSON.stringify({
        CredentialID: id,
        dataHash: validHash,
        Status: 'active',
        IssuerID: 'IssuerMSP'
      }));
    }
  };
  setContractInstance(mockContract);

  try {
    const initialHeapMb = process.memoryUsage().heapUsed / 1024 / 1024;
    const burstCount = 150;

    // Send 150 concurrent requests
    const promises = Array.from({ length: burstCount }, () =>
      fetch(`http://127.0.0.1:${port}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId: testId,
          dataHash: validHash,
          signature: 'abcd',
          publicKeyId: '12345678901234567890123456789012'
        })
      })
    );

    const responses = await Promise.all(promises);
    assert.equal(responses.length, burstCount);

    for (const r of responses) {
      assert.equal(r.status, 200, 'All burst requests must complete with 200 OK');
      const body = await r.json();
      assert.equal(body.valid, true);
    }

    const finalHeapMb = process.memoryUsage().heapUsed / 1024 / 1024;
    const heapDiffMb = finalHeapMb - initialHeapMb;

    // Memory growth must be bounded (< 60MB under 150 concurrent requests)
    assert.ok(
      heapDiffMb < 60,
      `Excessive memory growth under burst load: ${heapDiffMb.toFixed(2)} MB`
    );
  } finally {
    await new Promise(r => server.close(r));
    await new Promise(r => mockCrypto.close(r));
  }
});
