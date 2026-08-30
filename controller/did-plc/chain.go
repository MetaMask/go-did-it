package didplcctl

import (
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"github.com/MetaMask/go-did-it/crypto"
)

// The rules an operation log has to satisfy. These are free functions and take no
// configuration: they neither touch the network nor consult a key policy, because by the
// time an operation reaches them it has been parsed and its rotation keys decoded.

// verifySig checks sig (unpadded base64url) against unsigned using the given rotation
// keys, and returns the index of the key that verified. That index is the key's
// authority: a lower index outranks a higher one.
func verifySig(keys []rotationKey, unsigned []byte, sig string) (int, error) {
	// The specification requires unpadded base64url, so RawURLEncoding is what rejects a
	// signature carrying '=' padding.
	rawSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return -1, fmt.Errorf("%w: decoding signature: %w", ErrInvalidChain, err)
	}
	if len(rawSig) != signatureBytes {
		return -1, fmt.Errorf("%w: signature must be %d bytes, got %d", ErrInvalidChain, signatureBytes, len(rawSig))
	}
	if len(keys) == 0 {
		return -1, fmt.Errorf("%w: no rotation key is authorized to sign this operation", ErrInvalidChain)
	}
	for i, k := range keys {
		// did:plc requires low-S signatures, so a high-S one is refused even though the
		// ECDSA maths would accept it.
		if k.pub.VerifyBytes(unsigned, rawSig, crypto.WithEcdsaLowSSig()) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("%w: signature matches none of the %d authorized rotation keys", ErrInvalidChain, len(keys))
}

// checkGenesisOp verifies the operation a history starts with: it must point at no
// predecessor, must establish a state, must hash to the DID being asked about, and must be
// signed by one of its own rotation keys.
//
// That hash is what ties a history to its DID. Without it the rest of the validation is
// circular: a registry could serve a perfectly self-consistent history, signed throughout
// by its own keys, for any DID it cared to name.
func checkGenesisOp(didStr string, p *preparedOp) error {
	if p.prevCID != nil {
		return fmt.Errorf("%w: the first operation has prev=%s, expected null", ErrInvalidChain, *p.prevCID)
	}
	if p.isTombstone() {
		return fmt.Errorf("%w: the first operation is a tombstone", ErrInvalidChain)
	}
	if derived := deriveDID(p.signed); derived != didStr {
		return fmt.Errorf("%w: the genesis operation hashes to %s, not %s", ErrInvalidChain, derived, didStr)
	}
	if _, err := verifySig(p.rotKeys, p.unsigned, p.sig); err != nil {
		return fmt.Errorf("genesis operation: %w", err)
	}
	return nil
}

// nullificationAuthority returns the rotation keys allowed to sign an operation that forks
// the history away from disputed, the first operation such a fork would nullify.
//
// Only a key outranking the one that signed disputed may do that, so the answer is the
// prefix of base's rotation keys ahead of the disputed signer.
func nullificationAuthority(base, disputed *AuditEntry) ([]rotationKey, error) {
	forkKeys := base.prepared.rotKeys
	signerIdx, err := verifySig(forkKeys, disputed.prepared.unsigned, disputed.prepared.sig)
	if err != nil {
		return nil, fmt.Errorf("the operation it would nullify (%s) is not validly signed: %w", disputed.CID, err)
	}
	if signerIdx == 0 {
		return nil, fmt.Errorf("%w: %s was signed by the highest-authority rotation key, so nothing can nullify it",
			ErrInvalidChain, disputed.CID)
	}
	return forkKeys[:signerIdx], nil
}

// validateOperationLog verifies the canonical operation log of a DID (GET /:did/log,
// which omits nullified operations) and returns the state it ends on.
//
// It applies the three rules that make the log self-authenticating: the DID is the hash
// of the genesis operation, every operation points at its predecessor, and every
// operation is signed by a rotation key of that predecessor. It returns [ErrDeactivated]
// if the DID has been tombstoned.
func validateOperationLog(didStr string, ops []*preparedOp) (Head, error) {
	if len(ops) == 0 {
		return Head{}, fmt.Errorf("%w: empty operation log for %s", ErrInvalidChain, didStr)
	}
	if err := checkGenesisOp(didStr, ops[0]); err != nil {
		return Head{}, err
	}
	cid, err := computeCID(ops[0].signed)
	if err != nil {
		return Head{}, err
	}
	head := Head{CID: cid, Op: *ops[0].op, rotKeys: ops[0].rotKeys}

	for i, p := range ops[1:] {
		pos := i + 1
		if p.prevCID == nil {
			return Head{}, fmt.Errorf("%w: operation %d has prev=null, expected %s", ErrInvalidChain, pos, head.CID)
		}
		if *p.prevCID != head.CID {
			return Head{}, fmt.Errorf("%w: operation %d points at %s, expected %s", ErrInvalidChain, pos, *p.prevCID, head.CID)
		}
		// Authority comes from the operation being built on, never from the operation
		// itself: otherwise anyone could install their own rotation keys and self-sign.
		if _, err := verifySig(head.rotKeys, p.unsigned, p.sig); err != nil {
			return Head{}, fmt.Errorf("operation %d: %w", pos, err)
		}
		cid, err := computeCID(p.signed)
		if err != nil {
			return Head{}, err
		}
		if p.isTombstone() {
			// A tombstone ends the DID: nothing may follow it.
			if pos != len(ops)-1 {
				return Head{}, fmt.Errorf("%w: the tombstone at operation %d is followed by %d more operation(s)",
					ErrInvalidChain, pos, len(ops)-1-pos)
			}
			return Head{}, ErrDeactivated
		}
		head = Head{CID: cid, Op: *p.op, rotKeys: p.rotKeys}
	}
	return head, nil
}

// validateAuditLog replays the full audit log (GET /:did/log/audit), forks included, and
// checks every rule the registry is supposed to have enforced when it accepted each
// operation: the rules of [validateOperationLog], plus, for each operation
// that nullified others, that it was signed by a rotation key outranking the one that
// signed the first operation it nullified, and that it landed inside the recovery window.
//
// Finally the nullified flags the registry reported are compared against the replay, so
// a registry cannot quietly disown an operation it did accept.
//
// The timestamps this relies on are the registry's own and are not signed, so the window
// and ordering checks hold the registry to its account of events rather than proving
// anything on their own.
func validateAuditLog(didStr string, entries []AuditEntry) error {
	// canon is the canonical history as it stood after each entry was applied.
	var canon []*AuditEntry
	// nullified is the replay's verdict for each CID, to be compared with the registry's.
	nullified := make(map[string]bool, len(entries))

	for i := range entries {
		e := &entries[i]
		p := e.prepared
		if e.DID != didStr {
			return fmt.Errorf("%w: entry %d is for %s, not %s", ErrInvalidChain, i, e.DID, didStr)
		}
		computed, err := computeCID(p.signed)
		if err != nil {
			return fmt.Errorf("entry %d: computing CID: %w", i, err)
		}
		if computed != e.CID {
			return fmt.Errorf("%w: entry %d reports CID %s, computed %s", ErrInvalidChain, i, e.CID, computed)
		}
		// Not a protocol rule the registry could break on its own — a repeated operation
		// trips one of the checks below whichever way it is arranged. It guards this
		// replay instead: the verdicts are keyed by CID, so a repeat would overwrite one.
		if _, dup := nullified[e.CID]; dup {
			return fmt.Errorf("%w: entry %d repeats CID %s", ErrInvalidChain, i, e.CID)
		}

		if len(canon) == 0 {
			if err := checkGenesisOp(didStr, p); err != nil {
				return err
			}
			canon = append(canon, e)
			nullified[e.CID] = false
			continue
		}

		if p.prevCID == nil {
			return fmt.Errorf("%w: entry %d has prev=null but is not the first operation", ErrInvalidChain, i)
		}
		idx := slices.IndexFunc(canon, func(c *AuditEntry) bool { return c.CID == *p.prevCID })
		if idx < 0 {
			return fmt.Errorf("%w: entry %d points at %s, which is not in the canonical history",
				ErrInvalidChain, i, *p.prevCID)
		}
		base := canon[idx]
		if base.prepared.isTombstone() {
			return fmt.Errorf("%w: entry %d builds on tombstone %s", ErrInvalidChain, i, base.CID)
		}
		// Cloned because the append below overwrites canon from idx+1 onwards.
		forked := slices.Clone(canon[idx+1:])

		if len(forked) == 0 {
			if _, err := verifySig(base.prepared.rotKeys, p.unsigned, p.sig); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
		} else {
			// A recovery: it drops everything after the fork point, which only a key
			// outranking the signer of the first dropped operation may do.
			disputed := forked[0]
			authorized, err := nullificationAuthority(base, disputed)
			if err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
			if _, err := verifySig(authorized, p.unsigned, p.sig); err != nil {
				return fmt.Errorf("entry %d: a recovery must be signed by a rotation key outranking the one that signed %s: %w",
					i, disputed.CID, err)
			}
			if last := canon[len(canon)-1]; !e.CreatedAt.After(last.CreatedAt) {
				return fmt.Errorf("%w: entry %d is dated %s, which is not after the %s of the operation it supersedes",
					ErrInvalidChain, i, e.CreatedAt, last.CreatedAt)
			}
			if lapsed := e.CreatedAt.Sub(disputed.CreatedAt); lapsed > recoveryWindow {
				return fmt.Errorf("%w: entry %d rewrites history %s after the operation it nullifies, past the %s recovery window",
					ErrInvalidChain, i, lapsed, recoveryWindow)
			}
			for _, f := range forked {
				nullified[f.CID] = true
			}
		}
		canon = append(canon[:idx+1], e)
		nullified[e.CID] = false
	}

	for i, e := range entries {
		if e.Nullified != nullified[e.CID] {
			return fmt.Errorf("%w: entry %d (%s) is reported as nullified=%t, but the replay says %t",
				ErrInvalidChain, i, e.CID, e.Nullified, nullified[e.CID])
		}
	}
	return nil
}

// recoveryAuthority resolves the state a recovery will fork from, and the rotation keys
// allowed to sign it: a prefix of the fork point's rotation keys, and only within the
// recovery window counted from the first operation being dropped.
func recoveryAuthority(entries []AuditEntry, forkCID string) (*Op, []rotationKey, error) {
	canon := make([]*AuditEntry, 0, len(entries))
	for i := range entries {
		if !entries[i].Nullified {
			canon = append(canon, &entries[i])
		}
	}
	idx := slices.IndexFunc(canon, func(e *AuditEntry) bool { return e.CID == forkCID })
	if idx < 0 {
		return nil, nil, fmt.Errorf("fork CID %s is not in the canonical history", forkCID)
	}
	fork := canon[idx]
	if fork.prepared.isTombstone() {
		return nil, nil, fmt.Errorf("cannot fork from %s: it is a tombstone", forkCID)
	}

	if idx == len(canon)-1 {
		// Nothing to nullify: this is an ordinary update that happens to name its prev.
		return fork.Op, fork.prepared.rotKeys, nil
	}
	disputed := canon[idx+1]
	authorized, err := nullificationAuthority(fork, disputed)
	if err != nil {
		return nil, nil, err
	}
	// The registry would refuse a late recovery anyway; catching it here spells out why,
	// and avoids signing an operation that cannot be accepted.
	if lapsed := time.Since(disputed.CreatedAt); lapsed > recoveryWindow {
		return nil, nil, fmt.Errorf("cannot nullify %s: it is %s old, past the %s recovery window",
			disputed.CID, lapsed.Round(time.Second), recoveryWindow)
	}
	return fork.Op, authorized, nil
}
