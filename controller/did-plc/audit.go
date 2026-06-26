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
	Op       *Op
	prepared *auditPrepared
}

// auditPrepared holds the precomputed CBOR bytes and metadata needed to
// validate a single audit log entry. Built once in fetchAuditLog and consumed
// by validateChain without any further JSON parsing.
type auditPrepared struct {
	signed    []byte
	unsigned  []byte
	prevCID   *string
	signature string
	rotKeys   []string // did:key strings; nil for plc_tombstone
}

// parseAuditEntry parses a raw audit log JSON entry into the public Op and the
// internal auditPrepared. Returns (nil, prepared, nil) for tombstone operations.
// For plc_operation (the common case) only a single JSON unmarshal is performed.
func parseAuditEntry(data json.RawMessage) (*Op, *auditPrepared, error) {
	// Unmarshal into opJSON first: it carries the Type field and all plc_operation
	// fields, so the common case needs no second parse.
	var fields opJSON
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, nil, err
	}
	switch fields.Type {
	case "plc_operation":
		op, err := opFromJSON(fields)
		if err != nil {
			return nil, nil, fmt.Errorf("plc_operation keys: %w", err)
		}
		prep, err := buildPreparedOp(fields, data)
		if err != nil {
			return nil, nil, fmt.Errorf("plc_operation CBOR: %w", err)
		}
		return op, &auditPrepared{
			signed:    prep.signed,
			unsigned:  prep.unsigned,
			prevCID:   prep.prevCID,
			signature: prep.signature,
			rotKeys:   prep.rotKeys,
		}, nil

	case "plc_tombstone":
		ts, err := parseSignedTombstone(data)
		if err != nil {
			return nil, nil, err
		}
		return nil, &auditPrepared{
			signed:    ts.signed,
			unsigned:  ts.unsigned,
			prevCID:   &ts.prevCID,
			signature: ts.signature,
			// rotKeys is nil: tombstone carries no keys of its own
		}, nil

	case "create":
		var leg legacyCreateOp
		if err := json.Unmarshal(data, &leg); err != nil {
			return nil, nil, fmt.Errorf("legacy create: %w", err)
		}
		op, err := leg.toUnsignedOp()
		if err != nil {
			return nil, nil, fmt.Errorf("legacy create keys: %w", err)
		}
		signed, unsigned, err := leg.encode()
		if err != nil {
			return nil, nil, fmt.Errorf("legacy create CBOR: %w", err)
		}
		return op, &auditPrepared{
			signed:    signed,
			unsigned:  unsigned,
			prevCID:   leg.Prev,
			signature: leg.Sig,
			rotKeys:   []string{leg.RecoveryKey, leg.SigningKey},
		}, nil

	default:
		return nil, nil, fmt.Errorf("unknown operation type %q", fields.Type)
	}
}

// validateChain verifies a sequence of audit log entries for a single DID.
func (r *Registry) validateChain(entries []AuditEntry) error {
	var prevCID *string
	var prevRotKeys []string
	for i, entry := range entries {
		if entry.Nullified {
			continue
		}
		p := entry.prepared
		// Tombstone (rotKeys == nil): signature must verify against the previous op's keys.
		verifyKeys := p.rotKeys
		if verifyKeys == nil {
			verifyKeys = prevRotKeys
		}
		if err := r.verifyEntry(entry.CID, prevCID, p.signed, p.unsigned, p.prevCID, p.signature, verifyKeys); err != nil {
			return fmt.Errorf("entry %d (CID %s): %w", i, entry.CID, err)
		}
		cid := entry.CID
		prevCID = &cid
		if p.rotKeys != nil {
			prevRotKeys = p.rotKeys
		}
	}
	return nil
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
