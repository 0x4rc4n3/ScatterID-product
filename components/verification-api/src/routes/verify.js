import { getCredentialById, getCredentialByDataHash } from '../db/models.js';
import { queryProof } from '../chain/fabric.js';

export async function verifyRoute(req, res) {
  try {
    const { dataHash, credentialId } = req.body;

    if (!dataHash && !credentialId) {
      return res.status(400).json({
        error: 'Invalid parameter: either dataHash (64-character hex string) or credentialId (UUID v4) is required',
        code: 'INVALID_PARAMETER',
      });
    }

    if (dataHash !== undefined && (typeof dataHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(dataHash))) {
      return res.status(400).json({
        error: 'Invalid parameter: dataHash must be a 64-character hex string',
        code: 'INVALID_PARAMETER',
      });
    }

    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (credentialId !== undefined && (typeof credentialId !== 'string' || !uuidRegex.test(credentialId))) {
      return res.status(400).json({
        error: 'Invalid parameter: credentialId must be a valid UUID v4',
        code: 'INVALID_PARAMETER',
      });
    }

    const normalizedHash = dataHash ? dataHash.trim().toLowerCase() : null;
    const normalizedId = credentialId ? credentialId.trim().toLowerCase() : null;

    let record = null;
    if (normalizedId) {
      record = await getCredentialById(normalizedId);
    } else {
      record = await getCredentialByDataHash(normalizedHash);
    }

    if (!record) {
      return res.status(404).json({
        error: 'Credential not found',
        code: 'NOT_FOUND',
      });
    }

    const recDataHash = record.dataHash;
    const recIssuedAt = record.issuedAt;

    if (normalizedHash && recDataHash.toLowerCase() !== normalizedHash) {
      return res.status(200).json({
        valid: false,
        anchorStatus: 'tampered_hash',
        issuedAt: recIssuedAt,
        reason: 'Provided hash does not match stored hash',
      });
    }

    let anchorStatus = record.status;
    let isAnchoredOnChain = false;

    // Fail-secure: query Hyperledger Fabric on-chain anchor
    try {
      const fabricRecord = await queryProof(record.id);
      anchorStatus = fabricRecord.status || fabricRecord.Status;
      isAnchoredOnChain = true;

      if (fabricRecord.dataHash && fabricRecord.dataHash.toLowerCase() !== recDataHash.toLowerCase()) {
        return res.status(200).json({
          valid: false,
          anchorStatus: 'tampered_hash',
          issuedAt: recIssuedAt,
          reason: 'Ledger data hash mismatch',
        });
      }

      if (anchorStatus === 'revoked') {
        return res.status(200).json({
          valid: false,
          anchorStatus: 'revoked',
          issuedAt: recIssuedAt,
          reason: 'Credential has been revoked on the ledger',
        });
      }
    } catch (err) {
      // Ledger query failed or unreachable: NEVER fail open
      if (record.status === 'anchored') {
        anchorStatus = 'ledger_unreachable';
      }
    }

    try {
      const cryptoUrl = process.env.CRYPTO_SERVICE_URL || 'https://localhost:5001';
      const cryptoApiKey = process.env.CRYPTO_SERVICE_API_KEY || '';
      const cryptoTimeoutMs = parseInt(process.env.CRYPTO_SERVICE_TIMEOUT_MS, 10) || 5000;
      
      const payload = {
        dataHash: recDataHash,
        signature: record.signature,
        publicKeyId: record.publicKeyId  // always from registry, never from caller
      };
      
      const response = await fetch(`${cryptoUrl}/verify_hash`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${cryptoApiKey}`,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(cryptoTimeoutMs),
      });

      if (!response.ok) {
        return res.status(200).json({
          valid: false,
          anchorStatus,
          issuedAt: recIssuedAt,
          reason: 'Crypto microservice verification failed',
        });
      }

      const result = await response.json();
      
      // Strict Fail-Closed Rule (ZERO EXCEPTIONS):
      // Valid iff cryptographic signature is valid AND ledger anchor is active on-chain.
      // SECURITY: No environment-based bypass. If the ledger is unreachable,
      // the credential MUST resolve to invalid. Test environments should mock
      // the Fabric client via dependency injection, not short-circuit validation.
      const isSignatureValid = result && result.valid === true;
      const isLedgerActive = isAnchoredOnChain &&
        (anchorStatus === 'active' || anchorStatus === 'anchored');
      const isValid = isSignatureValid && isLedgerActive;

      let reason;
      if (!isValid) {
        if (!isSignatureValid) {
          reason = result.reason || 'Cryptographic signature is invalid';
        } else if (anchorStatus === 'revoked') {
          reason = 'Credential has been revoked on the ledger';
        } else if (anchorStatus === 'ledger_unreachable') {
          reason = 'Hyperledger Fabric ledger is currently unreachable to verify anchor';
        } else {
          reason = `Credential anchor status is '${anchorStatus}' (must be 'active')`;
        }
      }

      return res.status(200).json({
        valid: isValid,
        anchorStatus,
        issuedAt: recIssuedAt,
        reason,
      });
    } catch (err) {
      if (err.name === 'TimeoutError') {
        return res.status(504).json({
          error: 'Cryptographic authority request timed out',
          code: 'CRYPTO_SERVICE_TIMEOUT',
        });
      }
      return res.status(502).json({
        error: 'Cryptographic authority unreachable',
        code: 'CRYPTO_SERVICE_UNREACHABLE',
      });
    }
  } catch (globalErr) {
    return res.status(500).json({
      error: 'Internal Server Error',
      code: 'INTERNAL_ERROR',
    });
  }
}
