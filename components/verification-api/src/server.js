// TLS trust for crypto-service is established via NODE_EXTRA_CA_CERTS
// pointing to the ScatterID internal CA cert (ca.crt). Never disable
// certificate verification globally.
import http from 'http';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { timingSafeEqual, createHash } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { issueRoute, retryAnchorRoute } from './routes/issue.js';
import { statusRoute } from './routes/status.js';
import { verifyRoute } from './routes/verify.js';
import { revokeRoute } from './routes/revoke.js';
import { getAllCredentials, getAuditLogs } from './db/models.js';
import { reconcileLedger, getReconciliationState, startPeriodicReconciliation } from './reconcile.js';
import { getProofHistory } from './chain/fabric.js';

const VERIFICATION_API_KEY = process.env.VERIFICATION_API_KEY || '';
const REVOKE_API_KEY = process.env.REVOKE_API_KEY || '';
const CRYPTO_SERVICE_API_KEY = process.env.CRYPTO_SERVICE_API_KEY || '';

// Fail fast at startup if required cryptographic access keys are unconfigured
if (!VERIFICATION_API_KEY) {
  console.error(
    'FATAL: VERIFICATION_API_KEY must be set. ' +
    'The verification-api cannot start without an inbound authentication key.'
  );
  process.exit(1);
}

if (!REVOKE_API_KEY) {
  console.error(
    'FATAL: REVOKE_API_KEY must be set. ' +
    'Irreversible on-chain revocation requires a dedicated administrative key.'
  );
  process.exit(1);
}

if (REVOKE_API_KEY === VERIFICATION_API_KEY) {
  console.error(
    'FATAL: REVOKE_API_KEY must not match VERIFICATION_API_KEY. ' +
    'Irreversible on-chain revocation requires an independent administrative key to maintain privilege separation.'
  );
  process.exit(1);
}

if (!CRYPTO_SERVICE_API_KEY) {
  console.error(
    'FATAL: CRYPTO_SERVICE_API_KEY must be set. ' +
    'The verification gateway requires an outbound API key to connect to the PQC crypto-service.'
  );
  process.exit(1);
}

const app = express();
app.use(express.json());
app.use(helmet());

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: process.env.NODE_ENV === 'test' ? 100000 : 60, // 60 requests per minute per IP in production
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later', code: 'RATE_LIMITED' }
});

app.use('/issue', apiLimiter);
app.use('/verify', apiLimiter);
app.use('/status', apiLimiter);
app.use('/credentials', apiLimiter);
app.use('/revoke', apiLimiter);
app.use('/audit', apiLimiter);
app.use('/reconciliation', apiLimiter);

/**
 * Timing-safe Bearer token middleware for operator endpoints.
 */
export function requireBearerAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized', code: 'MISSING_AUTH' });
  }

  const token = authHeader.slice(7);
  const tokenHash = createHash('sha256').update(token).digest();
  const keyHash   = createHash('sha256').update(VERIFICATION_API_KEY).digest();

  if (!timingSafeEqual(tokenHash, keyHash)) {
    return res.status(401).json({ error: 'Unauthorized', code: 'INVALID_AUTH' });
  }

  req.callerTier = 'bearer_api_key';
  next();
}

/**
 * Narrower-scoped authorization middleware for destructive on-chain revocation.
 * Supports X-Revoke-Key header or primary Bearer authentication matching REVOKE_API_KEY.
 */
export function requireRevokeAuth(req, res, next) {
  const explicitRevokeKey = req.headers['x-revoke-key'];
  const authHeader = req.headers.authorization;

  const candidateKey = explicitRevokeKey || (authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null);

  if (!candidateKey) {
    return res.status(401).json({ error: 'Revocation key required', code: 'MISSING_REVOKE_AUTH' });
  }

  const candidateHash = createHash('sha256').update(candidateKey).digest();
  const expectedHash = createHash('sha256').update(REVOKE_API_KEY).digest();

  if (!timingSafeEqual(candidateHash, expectedHash)) {
    return res.status(403).json({ error: 'Forbidden: Invalid revocation authorization key', code: 'REVOCATION_UNAUTHORIZED' });
  }

  req.callerTier = 'revoke_api_key';
  next();
}

// Health check endpoint (unauthenticated)
app.get('/healthz', (req, res) => {
  res.json({
    status: 'ok',
    service: 'verification-api'
  });
});

// /verify is intentionally open to unauthenticated callers
app.post('/verify', verifyRoute);

// All write endpoints and administrative logs require scoped authentication
app.post('/issue', requireBearerAuth, issueRoute);
app.post('/issue/:credentialId/retry-anchor', requireBearerAuth, retryAnchorRoute);
app.get('/status/:id', requireBearerAuth, statusRoute);
app.post('/revoke', requireRevokeAuth, revokeRoute);

app.get('/credentials', requireBearerAuth, async (req, res) => {
  try {
    const credentials = await getAllCredentials();
    res.json({ success: true, credentials });
  } catch (err) {
    console.error('Failed to get credentials:', err.stack || err.message);
    res.status(500).json({ success: false, error: 'Internal Server Error', credentials: [] });
  }
});

app.get('/credentials/:credentialId/history', requireBearerAuth, async (req, res) => {
  try {
    const { credentialId } = req.params;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!credentialId || !uuidRegex.test(credentialId)) {
      return res.status(400).json({
        error: 'Invalid parameter: credentialId must be a valid UUID v4',
        code: 'INVALID_PARAMETER',
      });
    }
    const history = await getProofHistory(credentialId.trim().toLowerCase());
    res.json({ success: true, credentialId: credentialId.trim().toLowerCase(), history });
  } catch (err) {
    res.status(502).json({
      success: false,
      error: `Failed to retrieve ledger history: ${err.message}`,
      code: 'LEDGER_QUERY_FAILED'
    });
  }
});

app.get('/audit', requireBearerAuth, (req, res) => {
  const rawLimit = parseInt(req.query.limit, 10);
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 200) : 50;
  const logs = getAuditLogs(limit);
  res.json({ success: true, count: logs.length, logs });
});

app.get('/reconciliation', requireBearerAuth, (req, res) => {
  res.json({ success: true, ...getReconciliationState() });
});

app.post('/reconciliation/run', requireBearerAuth, async (req, res) => {
  try {
    const state = await reconcileLedger();
    res.json({ success: true, ...state });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export function configureServerTimeouts(server) {
  const socketTimeout = parseInt(process.env.SERVER_SOCKET_TIMEOUT_MS, 10) || 15000;
  server.headersTimeout = parseInt(process.env.SERVER_HEADERS_TIMEOUT_MS, 10) || 10000;
  server.requestTimeout = parseInt(process.env.SERVER_REQUEST_TIMEOUT_MS, 10) || 30000;
  server.keepAliveTimeout = 5000;
  server.setTimeout(socketTimeout, (socket) => {
    socket.destroy();
  });
  return server;
}

export function createServer() {
  const server = http.createServer(app);
  return configureServerTimeouts(server);
}

export { app };

const __filename = fileURLToPath(import.meta.url);
const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;

if (isMain) {
  const PORT = process.env.PORT || 3000;
  const server = createServer();
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Verification API listening on port ${PORT}`);
    startPeriodicReconciliation(180000); // Reconcile every 3 minutes
  });

  process.on('SIGTERM', () => {
    console.log('Verification API received SIGTERM, exiting...');
    process.exit(0);
  });

  process.on('SIGINT', () => {
    console.log('Verification API received SIGINT, exiting...');
    process.exit(0);
  });
}
