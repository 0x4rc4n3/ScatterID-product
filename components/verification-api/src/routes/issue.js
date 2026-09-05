import { randomUUID } from 'crypto';
import { createCredential, updateAnchorInfo, updateStatus, getCredentialById, getCredentialByIdempotencyKey, recordAuditLog } from '../db/models.js';
import { anchorProof } from '../chain/fabric.js';

export async function issueRoute(req, res) {
  try {
    const { dataHash, idempotencyKey } = req.body;

    if (!dataHash || typeof dataHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(dataHash)) {
      return res.status(400).json({
        error: 'Invalid parameter: dataHash is required and must be a 64-character hex string',
        code: 'INVALID_PARAMETER',
      });
    }

    const normalizedHash = dataHash.trim().toLowerCase();
    
    if (idempotencyKey) {
      const existing = await getCredentialByIdempotencyKey(idempotencyKey);
      if (existing) {
        return res.status(200).json({
          status: existing.status,
          credentialId: existing.id,
          dataHash: existing.dataHash,
          algorithm: existing.algorithm,
          anchorTxId: existing.anchorTxId,
          publicKeyId: existing.publicKeyId,
          signature: existing.signature,
          issuedAt: existing.issuedAt
        });
      }
    }

    const credentialId = randomUUID();

    let credential;
    try {
      const cryptoUrl = process.env.CRYPTO_SERVICE_URL || 'https://localhost:5001';
      const cryptoApiKey = process.env.CRYPTO_SERVICE_API_KEY || '';
      const cryptoTimeoutMs = parseInt(process.env.CRYPTO_SERVICE_TIMEOUT_MS, 10) || 5000;
      const response = await fetch(`${cryptoUrl}/sign_hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${cryptoApiKey}`,
        },
        body: JSON.stringify({ dataHash: normalizedHash, credentialId }),
        signal: AbortSignal.timeout(cryptoTimeoutMs),
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        recordAuditLog({
          credentialId,
          action: 'issue',
          status: 'failed',
          details: { error: 'Cryptographic signing failure', details: errJson },
          callerTier: 'bearer_api_key'
        });
        return res.status(502).json({
          error: 'Cryptographic processing failed',
          code: 'CRYPTO_SERVICE_ERROR',
          details: errJson
        });
      }

      credential = await response.json();
    } catch (err) {
      const isTimeout = err.name === 'TimeoutError';
      recordAuditLog({
        credentialId,
        action: 'issue',
        status: 'failed',
        details: { error: isTimeout ? 'Cryptographic authority timed out' : 'Cryptographic authority unreachable', message: err.message },
        callerTier: 'bearer_api_key'
      });
      return res.status(isTimeout ? 504 : 502).json({
        error: isTimeout ? 'Cryptographic authority request timed out' : 'Cryptographic authority unreachable',
        code: isTimeout ? 'CRYPTO_SERVICE_TIMEOUT' : 'CRYPTO_SERVICE_UNREACHABLE',
      });
    }

    const insertResult = await createCredential({
      id: credentialId,
      dataHash: credential.dataHash,
      algorithm: credential.algorithm,
      signature: credential.signature,
      publicKeyId: credential.publicKeyId,
      anchorTxId: null,
      status: 'pending',
      issuedAt: credential.issuedAt,
      idempotencyKey: idempotencyKey || null
    });

    // Handle race condition: if concurrent request won the insert race, return the existing record
    if (insertResult && insertResult.changes === 0 && idempotencyKey) {
      const existing = await getCredentialByIdempotencyKey(idempotencyKey);
      if (existing) {
        return res.status(200).json({
          status: existing.status,
          credentialId: existing.id,
          dataHash: existing.dataHash,
          algorithm: existing.algorithm,
          anchorTxId: existing.anchorTxId,
          publicKeyId: existing.publicKeyId,
          signature: existing.signature,
          issuedAt: existing.issuedAt
        });
      }
    }

    let anchorTxId = null;
    let anchorError = null;

    try {
      anchorTxId = await anchorProof(credentialId, credential.dataHash, 'IssuerMSP');
      await updateAnchorInfo(credentialId, anchorTxId, 'anchored');
      recordAuditLog({
        credentialId,
        action: 'issue',
        status: 'anchored',
        details: { txId: anchorTxId, dataHash: credential.dataHash },
        callerTier: 'bearer_api_key'
      });
    } catch (err) {
      anchorError = err.message || 'Fabric ledger anchor failed';
      await updateStatus(credentialId, 'anchor_failed');
      recordAuditLog({
        credentialId,
        action: 'issue',
        status: 'anchor_failed',
        details: { reason: anchorError, dataHash: credential.dataHash },
        callerTier: 'bearer_api_key'
      });
    }

    if (anchorError) {
      // 202 Accepted: Signing succeeded and credential is saved, but ledger anchor failed and must be retried
      return res.status(202).json({
        status: 'anchor_failed',
        reason: anchorError,
        credentialId,
        dataHash: credential.dataHash,
        algorithm: credential.algorithm,
        publicKeyId: credential.publicKeyId,
        signature: credential.signature,
        anchorTxId: null,
        issuedAt: credential.issuedAt
      });
    }

    return res.status(201).json({
      status: 'anchored',
      credentialId,
      dataHash: credential.dataHash,
      algorithm: credential.algorithm,
      publicKeyId: credential.publicKeyId,
      signature: credential.signature,
      anchorTxId,
      issuedAt: credential.issuedAt
    });
  } catch (globalErr) {
    return res.status(500).json({
      error: 'Internal Server Error',
      code: 'INTERNAL_ERROR',
    });
  }
}

export async function retryAnchorRoute(req, res) {
  try {
    const { credentialId } = req.params;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!credentialId || !uuidRegex.test(credentialId)) {
      return res.status(400).json({
        error: 'Invalid parameter: credentialId must be a valid UUID v4',
        code: 'INVALID_PARAMETER',
      });
    }

    const normalizedId = credentialId.trim().toLowerCase();
    const record = await getCredentialById(normalizedId);
    if (!record) {
      return res.status(404).json({
        error: 'Credential not found',
        code: 'NOT_FOUND',
      });
    }

    if (record.status === 'anchored' && record.anchorTxId) {
      return res.status(200).json({
        status: 'anchored',
        credentialId: record.id,
        anchorTxId: record.anchorTxId,
        message: 'Credential is already anchored on the ledger',
      });
    }

    if (record.status === 'revoked') {
      return res.status(400).json({
        error: 'Cannot anchor a revoked credential',
        code: 'INVALID_STATE',
      });
    }

    try {
      const anchorTxId = await anchorProof(record.id, record.dataHash, 'IssuerMSP');
      await updateAnchorInfo(record.id, anchorTxId, 'anchored');
      recordAuditLog({
        credentialId: record.id,
        action: 'retry_anchor',
        status: 'anchored',
        details: { txId: anchorTxId },
        callerTier: 'bearer_api_key'
      });

      return res.status(200).json({
        status: 'anchored',
        credentialId: record.id,
        anchorTxId,
        message: 'Credential successfully anchored on the ledger',
      });
    } catch (fabricErr) {
      await updateStatus(record.id, 'anchor_failed');
      recordAuditLog({
        credentialId: record.id,
        action: 'retry_anchor',
        status: 'anchor_failed',
        details: { error: fabricErr.message },
        callerTier: 'bearer_api_key'
      });

      return res.status(502).json({
        status: 'anchor_failed',
        error: `Ledger anchor retry failed: ${fabricErr.message}`,
        code: 'LEDGER_UNREACHABLE',
      });
    }
  } catch (err) {
    return res.status(500).json({
      error: 'Internal Server Error',
      code: 'INTERNAL_ERROR',
    });
  }
}
