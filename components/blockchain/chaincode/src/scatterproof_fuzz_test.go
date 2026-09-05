package main

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// FuzzAnchorProof executes native coverage-guided fuzzing on AnchorProof.
// Asserts that no combination of arbitrary strings causes a panic,
// and enforces all input validation and state invariants.
func FuzzAnchorProof(f *testing.F) {
	// Seed corpus with representative valid and boundary inputs
	f.Add("c9a646d3-9c61-4cc9-bc3d-5573752e25df", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "IssuerOrg", "2026-03-30T12:00:00Z", "IssuerMSP")
	f.Add("", "", "", "", "")
	f.Add("invalid-uuid", "short", "issuer", "bad-date", "OtherMSP")
	f.Add("C9A646D3-9C61-4CC9-BC3D-5573752E25DF", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "   IssuerOrg   ", "2026-03-30T12:00:00.123456Z", "IssuerMSP")
	f.Add("00000000-0000-4000-8000-000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "GovIssuer", "1970-01-01T00:00:00Z", "IssuerMSP")
	f.Add("ffffffff-ffff-4fff-bfff-ffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "Issuer", "2100-12-31T23:59:59Z", "IssuerMSP")
	f.Add("c9a646d3-9c61-4cc9-bc3d-5573752e25df", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "IssuerOrg", "1969-12-31T23:59:59Z", "IssuerMSP")
	f.Add("c9a646d3-9c61-4cc9-bc3d-5573752e25df", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "IssuerOrg", "2101-01-01T00:00:00Z", "IssuerMSP")
	f.Add("' OR 1=1; --", "\x00\x01\x02", stringsRepeat("A", 300), "not-a-timestamp", "EvilMSP")

	f.Fuzz(func(t *testing.T, credID, dataHash, issuerID, timestamp, mspID string) {
		contract := &SmartContract{}
		ctx := newMockContext(mspID)
		ctx.startTx("fuzz-tx-anchor")
		defer ctx.endTx("fuzz-tx-anchor")

		err := contract.AnchorProof(ctx, credID, dataHash, issuerID, timestamp)

		// Invariants:
		if err == nil {
			// 1. Authorization: Only IssuerMSP could succeed
			if mspID != "IssuerMSP" {
				t.Fatalf("INVARIANT VIOLATION: AnchorProof succeeded with non-issuer MSP: %q", mspID)
			}

			// 2. QueryProof must succeed and have active status
			proof, queryErr := contract.QueryProof(ctx, credID)
			if queryErr != nil {
				t.Fatalf("INVARIANT VIOLATION: QueryProof failed after successful anchor: %v", queryErr)
			}
			if proof.Status != "active" {
				t.Fatalf("INVARIANT VIOLATION: Anchored proof has non-active status: %q", proof.Status)
			}

			// 3. Replay Protection: Re-anchoring with identical credentialID must fail
			replayErr := contract.AnchorProof(ctx, credID, dataHash, issuerID, timestamp)
			if replayErr == nil {
				t.Fatalf("INVARIANT VIOLATION: Duplicate AnchorProof succeeded for credentialID: %q", credID)
			}
		}
	})
}

// FuzzRevokeProof executes native coverage-guided fuzzing on RevokeProof.
func FuzzRevokeProof(f *testing.F) {
	f.Add("c9a646d3-9c61-4cc9-bc3d-5573752e25df", "IssuerOrg", "IssuerMSP")
	f.Add("c9a646d3-9c61-4cc9-bc3d-5573752e25df", "WrongIssuer", "IssuerMSP")
	f.Add("c9a646d3-9c61-4cc9-bc3d-5573752e25df", "IssuerOrg", "AttackerMSP")
	f.Add("00000000-0000-0000-0000-000000000000", "", "")
	f.Add("non-existent-uuid-v4-0000-000000000000", "IssuerOrg", "IssuerMSP")

	f.Fuzz(func(t *testing.T, credID, reqIssuerID, mspID string) {
		contract := &SmartContract{}
		ctx := newMockContext(mspID)
		ctx.startTx("fuzz-tx-revoke")
		defer ctx.endTx("fuzz-tx-revoke")

		// First, pre-anchor an authentic credential using an authorized context
		authCtx := newMockContext("IssuerMSP")
		authCtx.stub = ctx.stub // share same world state
		authCtx.startTx("setup-anchor")
		_ = contract.AnchorProof(authCtx, validUUID, validHash, "IssuerOrg", "2026-03-30T12:00:00Z")
		authCtx.endTx("setup-anchor")

		err := contract.RevokeProof(ctx, credID, reqIssuerID)

		// Invariants:
		if err == nil {
			// 1. Authorization: Only IssuerMSP could succeed
			if mspID != "IssuerMSP" {
				t.Fatalf("INVARIANT VIOLATION: RevokeProof succeeded with unauthorized MSP %q", mspID)
			}
			// 2. Requesting issuer must match anchored issuer
			if reqIssuerID != "IssuerOrg" {
				t.Fatalf("INVARIANT VIOLATION: RevokeProof succeeded with mismatched issuer %q", reqIssuerID)
			}
			// 3. Credential must be validUUID
			normalizedID := strings.ToLower(strings.TrimSpace(credID))
			if normalizedID != validUUID {
				t.Fatalf("INVARIANT VIOLATION: RevokeProof succeeded on unanchored credential %q", credID)
			}
			// 4. Record status must now be revoked
			proof, queryErr := contract.QueryProof(ctx, validUUID)
			if queryErr != nil || proof.Status != "revoked" {
				t.Fatalf("INVARIANT VIOLATION: Revoked proof has status %v (err: %v)", proof, queryErr)
			}
			// 5. Monotonicity: Immediate second revocation MUST fail
			doubleRevokeErr := contract.RevokeProof(ctx, credID, reqIssuerID)
			if doubleRevokeErr == nil {
				t.Fatalf("INVARIANT VIOLATION: Second RevokeProof call succeeded on already revoked proof")
			}
		}
	})
}

// stringsRepeat helper to generate large inputs
func stringsRepeat(s string, count int) string {
	b := make([]byte, len(s)*count)
	for i := 0; i < count; i++ {
		copy(b[i*len(s):], s)
	}
	return string(b)
}

// TestProperty_MonotonicRevocation asserts the fundamental system invariant:
// Once a credential reaches the "revoked" state, NO sequence of operations
// (valid or invalid, authenticated or malicious) can ever transition it back to "active"
// or unanchored.
func TestProperty_MonotonicRevocation(t *testing.T) {
	contract := &SmartContract{}
	rng := rand.New(rand.NewSource(133742))

	const numTrials = 200
	const maxOpsPerTrial = 30

	for trial := 0; trial < numTrials; trial++ {
		// Generate random UUID v4 for this trial
		uuidBytes := make([]byte, 16)
		rng.Read(uuidBytes)
		uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40 // version 4
		uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80 // variant
		credID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:16])

		hashBytes := make([]byte, 32)
		rng.Read(hashBytes)
		dataHash := hex.EncodeToString(hashBytes)

		issuerID := fmt.Sprintf("Issuer-%d", rng.Intn(5))
		timestamp := "2026-03-30T12:00:00Z"

		ctx := newMockContext("IssuerMSP")
		ctx.startTx(fmt.Sprintf("trial-%d-init", trial))

		// Pre-condition: Anchor proof
		err := contract.AnchorProof(ctx, credID, dataHash, issuerID, timestamp)
		if err != nil {
			t.Fatalf("Trial %d: Failed to anchor: %v", trial, err)
		}
		ctx.endTx(fmt.Sprintf("trial-%d-init", trial))

		// Revoke the proof
		ctx.startTx(fmt.Sprintf("trial-%d-revoke", trial))
		err = contract.RevokeProof(ctx, credID, issuerID)
		if err != nil {
			t.Fatalf("Trial %d: Failed to revoke: %v", trial, err)
		}
		ctx.endTx(fmt.Sprintf("trial-%d-revoke", trial))

		// INVARIANT: State is now terminal "revoked".
		// Now execute a randomized sequence of operations attempting to perturb or reactivate state.
		numOps := rng.Intn(maxOpsPerTrial) + 5
		for op := 0; op < numOps; op++ {
			txName := fmt.Sprintf("trial-%d-op-%d", trial, op)
			opType := rng.Intn(5)

			ctx.startTx(txName)

			switch opType {
			case 0: // Attempt AnchorProof (replay or resurrect)
				callerMSP := []string{"IssuerMSP", "VerifierMSP", "AttackerMSP"}[rng.Intn(3)]
				ctx.clientIdentity = &mockClientIdentity{mspID: callerMSP, id: "actor"}
				newHash := hex.EncodeToString(hashBytes)
				_ = contract.AnchorProof(ctx, credID, newHash, issuerID, timestamp)

			case 1: // Attempt RevokeProof again
				callerMSP := []string{"IssuerMSP", "VerifierMSP", "AttackerMSP"}[rng.Intn(3)]
				ctx.clientIdentity = &mockClientIdentity{mspID: callerMSP, id: "actor"}
				reqIssuer := []string{issuerID, "OtherIssuer", ""}[rng.Intn(3)]
				_ = contract.RevokeProof(ctx, credID, reqIssuer)

			case 2: // QueryProof
				p, qErr := contract.QueryProof(ctx, credID)
				if qErr != nil {
					t.Fatalf("Trial %d Op %d: QueryProof unexpectedly failed: %v", trial, op, qErr)
				}
				if p.Status != "revoked" {
					t.Fatalf("CRITICAL INVARIANT VIOLATION: Proof %s transitioned from revoked to %q!", credID, p.Status)
				}

			case 3: // Query and verify hash equality
				p, qErr := contract.QueryProof(ctx, credID)
				if qErr != nil {
					t.Fatalf("Trial %d Op %d: QueryProof failed: %v", trial, op, qErr)
				}
				if subtle.ConstantTimeCompare([]byte(p.DataHash), []byte(dataHash)) != 1 {
					t.Fatalf("Trial %d Op %d: DataHash altered in state", trial, op)
				}
				if p.Status != "revoked" {
					t.Fatalf("CRITICAL INVARIANT VIOLATION: Proof %s status is not revoked: %s", credID, p.Status)
				}

			case 4: // ProofExists
				exists, eErr := contract.ProofExists(ctx, credID)
				if eErr != nil || !exists {
					t.Fatalf("Trial %d Op %d: ProofExists failed or returned false: %v", trial, op, eErr)
				}
			}

			ctx.endTx(txName)

			// Post-operation verification: Status must STILL be "revoked"
			proof, pErr := contract.QueryProof(ctx, credID)
			if pErr != nil || proof.Status != "revoked" {
				t.Fatalf("CRITICAL INVARIANT VIOLATION at Op %d: Credential %s is no longer revoked! Proof: %+v, Err: %v",
					op, credID, proof, pErr)
			}
		}
	}
}

// TestProperty_VerificationPureFunction asserts that QueryProof is a pure mathematical
// reader of state: repeated invocations with identical parameters return bit-for-bit
// identical results and cause zero world-state mutation.
func TestProperty_VerificationPureFunction(t *testing.T) {
	contract := &SmartContract{}
	ctx := newMockContext("VerifierMSP")
	ctx.startTx("tx-pure-init")

	// Anchor active proof
	authCtx := newMockContext("IssuerMSP")
	authCtx.stub = ctx.stub
	authCtx.startTx("tx-pure-anchor")
	err := contract.AnchorProof(authCtx, validUUID, validHash, "IssuerOrg", "2026-03-30T12:00:00Z")
	if err != nil {
		t.Fatalf("Setup anchor failed: %v", err)
	}
	authCtx.endTx("tx-pure-anchor")

	// Read initial world state snapshot
	initialState, err := ctx.stub.GetState(validUUID)
	if err != nil || initialState == nil {
		t.Fatalf("Failed to fetch initial state: %v", err)
	}

	// Invoke QueryProof 500 times with identical inputs
	for i := 0; i < 500; i++ {
		ctx.startTx(fmt.Sprintf("tx-pure-query-%d", i))
		record, qErr := contract.QueryProof(ctx, validUUID)
		ctx.endTx(fmt.Sprintf("tx-pure-query-%d", i))

		if qErr != nil || record.Status != "active" || record.DataHash != validHash {
			t.Fatalf("Iteration %d: unexpected query result: record=%+v, err=%v", i, record, qErr)
		}

		// Verify that world state was NOT mutated
		currentState, _ := ctx.stub.GetState(validUUID)
		if string(currentState) != string(initialState) {
			t.Fatalf("INVARIANT VIOLATION: QueryProof mutated world state at iteration %d!", i)
		}
	}
}
