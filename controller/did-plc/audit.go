package did_plc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MetaMask/go-did-it/crypto"
)

// AuditEntry is one record from the did:plc audit log
// (GET https://plc.directory/:did/log/audit).
type AuditEntry struct {
	DID       string
	CID       string
	CreatedAt time.Time
	// Nullified is true when this operation was invalidated by a recovery
	// operation from a higher-authority rotation key within the 72-hour window.
	Nullified bool
	// Op is the decoded document content of the operation, or nil for tombstones.
	Op    *UnsignedOp
	rawOp json.RawMessage
}

// parseUnsignedOpFromRaw reconstructs a public UnsignedOp from a raw audit log JSON entry.
// Returns nil for tombstone operations.
func parseUnsignedOpFromRaw(raw json.RawMessage) (*UnsignedOp, error) {
	var typed struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return nil, err
	}
	switch typed.Type {
	case "plc_operation":
		s, err := parseSignedOp(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing plc_operation: %w", err)
		}
		return s.toUnsignedOp()
	case "plc_tombstone":
		return nil, nil
	case "create":
		var leg legacyCreateOp
		if err := json.Unmarshal(raw, &leg); err != nil {
			return nil, fmt.Errorf("parsing legacy create: %w", err)
		}
		return leg.toUnsignedOp()
	default:
		return nil, fmt.Errorf("unknown operation type %q", typed.Type)
	}
}

// validateChain verifies a sequence of audit log entries for a single DID.
func (r *Registry) validateChain(entries []AuditEntry) error {
	var prevCID *string
	for i, entry := range entries {
		if entry.Nullified {
			continue
		}
		if err := r.validateEntry(entry, prevCID); err != nil {
			return fmt.Errorf("entry %d (CID %s): %w", i, entry.CID, err)
		}
		cid := entry.CID
		prevCID = &cid
	}
	return nil
}

func (r *Registry) validateEntry(entry AuditEntry, expectedPrev *string) error {
	var typed struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(entry.rawOp, &typed); err != nil {
		return fmt.Errorf("parsing operation type: %w", err)
	}

	switch typed.Type {
	case "plc_operation":
		op, err := parseSignedOp(entry.rawOp)
		if err != nil {
			return fmt.Errorf("parsing plc_operation: %w", err)
		}
		return r.verifyEntry(entry.CID, expectedPrev, op.signed, op.unsigned, op.prevCID, op.signature, op.rotKeys)

	case "plc_tombstone":
		ts, err := parseSignedTombstone(entry.rawOp)
		if err != nil {
			return fmt.Errorf("parsing plc_tombstone: %w", err)
		}
		return r.verifyEntry(entry.CID, expectedPrev, ts.signed, ts.unsigned, &ts.prevCID, ts.signature, nil)

	case "create":
		var leg legacyCreateOp
		if err := json.Unmarshal(entry.rawOp, &leg); err != nil {
			return fmt.Errorf("parsing legacy create: %w", err)
		}
		signed, unsigned, err := leg.encode()
		if err != nil {
			return fmt.Errorf("encoding legacy create: %w", err)
		}
		return r.verifyEntry(entry.CID, expectedPrev, signed, unsigned, leg.Prev, leg.Sig, []string{leg.RecoveryKey, leg.SigningKey})

	default:
		return fmt.Errorf("unknown operation type %q", typed.Type)
	}
}

// verifyEntry runs the three invariants common to all operation types:
// CID integrity, prev-chain continuity, and signature validity.
func (r *Registry) verifyEntry(
	entryCID string,
	expectedPrev *string,
	signed, unsigned []byte,
	prevCID *string,
	signature string,
	rotKeys []string,
) error {
	// 1. CID
	computed, err := computeCID(signed)
	if err != nil {
		return fmt.Errorf("computing CID: %w", err)
	}
	if computed != entryCID {
		return fmt.Errorf("CID mismatch: entry reports %s, computed %s", entryCID, computed)
	}

	// 2. Prev chain
	switch {
	case expectedPrev == nil && prevCID == nil: // genesis ✓
	case expectedPrev == nil && prevCID != nil:
		return fmt.Errorf("expected genesis (prev=nil), got prev=%s", *prevCID)
	case expectedPrev != nil && prevCID == nil:
		return fmt.Errorf("expected prev=%s, got nil (genesis)", *expectedPrev)
	case *expectedPrev != *prevCID:
		return fmt.Errorf("prev mismatch: expected %s, got %s", *expectedPrev, *prevCID)
	}

	// 3. Signature
	rawSig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	if len(rawSig) != 64 {
		return fmt.Errorf("signature must be 64 bytes, got %d", len(rawSig))
	}
	const prefix = "did:key:"
	for _, didKey := range rotKeys {
		if !strings.HasPrefix(didKey, prefix) {
			continue
		}
		pub, err := r.rotationKeySet.PublicKeyFromMultibase(didKey[len(prefix):])
		if err != nil {
			continue
		}
		v, ok := pub.(crypto.PublicKeySigningBytes)
		if !ok {
			continue
		}
		if v.VerifyBytes(unsigned, rawSig, crypto.WithEcdsaLowSSig()) {
			return nil
		}
	}
	return fmt.Errorf("signature does not match any rotation key")
}
