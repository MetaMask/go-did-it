package didplcctl

import (
	"fmt"
	"slices"
	"time"
)

// AuditEntry is one record of the did:plc audit log (GET /:did/log/audit).
type AuditEntry struct {
	// DID is the DID the operation belongs to.
	DID string
	// CID identifies the operation, and is what the next operation points at.
	CID string
	// CreatedAt is when the registry accepted the operation. It is the registry's own
	// timestamp and is not covered by the operation's signature.
	CreatedAt time.Time
	// Nullified is true when a recovery operation, signed by a higher-authority rotation
	// key within the recovery window, forked the history before this operation and so
	// dropped it out of the canonical history.
	Nullified bool
	// State is the document state this operation established, or nil for a tombstone.
	State *State

	// prepared is the operation itself, parsed: its byte encodings and its decoded
	// rotation keys. The exported fields above are the caller's view of it — State is the
	// state it establishes, CID the registry's name for it — while the replay in
	// chain.validate needs what that view leaves out: the unsigned bytes a signature is
	// checked against, the signed bytes the CID is recomputed from, and the rotation keys
	// that decide who may sign the operation built on this one.
	//
	// Every entry this package produces has one, and nothing reads it that a caller could
	// reach with an AuditEntry of their own, since chain is unexported.
	prepared *operation
}

// Head is the state a new operation is built on: the DID's most recent operation and
// the document state it established.
type Head struct {
	// CID identifies the most recent operation, and becomes the prev of the next one.
	CID string
	// State is the document state that operation established.
	State State

	// rotKeys is State.RotationKeys in the form the signing and verification code needs:
	// the wire string to check a signer against, and the decoded key to check a signature
	// with.
	rotKeys []rotationKey
}

// chain is a DID's history as the registry reports it (GET /:did/log/audit): every
// operation the registry ever accepted, in acceptance order, nullified forks included.
//
// The prev links form a tree, not a line — a recovery branches off an earlier operation
// and everything after that point dies — while the slice itself is flat, in the order the
// registry accepted things:
//
//	slice:        op1     op2✗    op3✗    op4
//	                       ┌── op2 ── op3          nullified, still served, still here
//	prev links:   op1 ─────┤
//	                       └── op4                 the live path, in slice order
//
// [chain.canonical] is the live path, which is linear; everything else in this file is
// about proving that the registry's account of which branch died is the true one.
//
// It is the only history this package reads, because it is the only one that carries the
// evidence needed to check a recovery. The registry also serves the canonical history
// alone (GET /:did/log), but that endpoint drops exactly the operations a recovery
// nullified — so a fork made by an unauthorized key, or made after the recovery window
// closed, is indistinguishable there from an honest update.
//
// The methods below take no configuration: they neither touch the network nor consult a
// key policy, because by the time an operation reaches them it has been parsed and its
// rotation keys decoded.
type chain []AuditEntry

// canonical returns the entries still standing, in order: the live path through the tree,
// with everything a recovery nullified removed.
//
// It reports the registry's own verdict, so the result is a path only once
// [chain.validate] has passed. Nothing stops a registry from leaving two siblings both
// unflagged, in which case what comes back here is a branch, not a line.
func (c chain) canonical() []*AuditEntry {
	out := make([]*AuditEntry, 0, len(c))
	for i := range c {
		if !c[i].Nullified {
			out = append(out, &c[i])
		}
	}
	return out
}

// head returns the state a new operation should be built on: the last entry still
// standing, and the document state it established.
//
// It returns [ErrDeactivated] if that entry is a tombstone. The CID is recomputed from
// the operation rather than taken from the entry, so it holds whether or not the chain
// has been validated.
func (c chain) head() (Head, error) {
	canon := c.canonical()
	if len(canon) == 0 {
		return Head{}, fmt.Errorf("%w: empty operation log", ErrInvalidChain)
	}
	last := canon[len(canon)-1]
	if last.prepared.isTombstone() {
		return Head{}, ErrDeactivated
	}
	cid, err := last.prepared.cid()
	if err != nil {
		return Head{}, err
	}
	return Head{CID: cid, State: *last.State, rotKeys: last.prepared.rotKeys}, nil
}

// validate replays the chain and checks the rules that decide who controls the DID: the
// DID is the hash of the genesis operation, every operation points at an operation
// standing at the time, and every operation is signed by a rotation key of the one it
// points at. For an operation that nullified others it also checks that the signing key
// outranked the one that signed the first operation nullified, and that it landed inside
// the recovery window.
//
// Finally the nullified flags the registry reported are compared against the replay, so a
// registry cannot quietly disown an operation it did accept.
//
// What it deliberately does not check is the structural limits in spec.go — operation size,
// key and entry counts, string lengths, the syntax of services. Those bound what this
// package *writes*; a history is held to none of them, because the registry itself applies
// them only to an incoming operation and never when serving a stored log, so an operation
// predating a limit stays valid forever.
//
// minRotationKeys is not one of the registry's limits at all, only this package's guard
// against writing an operation that would freeze a DID, and the interop suite has a valid
// log whose last operation carries no rotation keys — so applying it here would make a real
// DID unreadable. See TestInteropPinsTheReadPathLenient, which also pins the converse: a
// duplicate rotation key is accepted on both paths, since the registry has never rejected
// one and real DIDs carry them.
//
// The timestamps this relies on are the registry's own and are not signed, so the window
// and ordering checks hold the registry to its account of events rather than proving
// anything on their own.
func (c chain) validate(didStr string) error {
	// canon is the canonical history as it stood after each entry was applied.
	var canon []*AuditEntry
	// nullified is the replay's verdict for each CID, to be compared with the registry's.
	nullified := make(map[string]bool, len(c))

	for i := range c {
		e := &c[i]
		p := e.prepared
		if e.DID != didStr {
			return fmt.Errorf("%w: entry %d is for %s, not %s", ErrInvalidChain, i, e.DID, didStr)
		}
		computed, err := p.cid()
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
			if err := p.checkGenesis(didStr); err != nil {
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
			// Authority comes from the operation being built on, never from this one.
			if _, err := p.verify(base.prepared.rotKeys); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
		} else {
			// A recovery: it drops everything after the fork point.
			disputed := forked[0]
			authorized, err := nullificationAuthority(base, disputed)
			if err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
			if _, err := p.verify(authorized); err != nil {
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

	for i, e := range c {
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
func (c chain) recoveryAuthority(forkCID string) (*State, []rotationKey, error) {
	canon := c.canonical()
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
		return fork.State, fork.prepared.rotKeys, nil
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
	return fork.State, authorized, nil
}

// nullificationAuthority returns the rotation keys allowed to sign an operation that forks
// the history away from disputed, the first operation such a fork would nullify.
//
// Only a key outranking the one that signed disputed may do that, so the answer is the
// prefix of base's rotation keys ahead of the disputed signer.
func nullificationAuthority(base, disputed *AuditEntry) ([]rotationKey, error) {
	forkKeys := base.prepared.rotKeys
	signerIdx, err := disputed.prepared.verify(forkKeys)
	if err != nil {
		return nil, fmt.Errorf("the operation it would nullify (%s) is not validly signed: %w", disputed.CID, err)
	}
	if signerIdx == 0 {
		return nil, fmt.Errorf("%w: %s was signed by the highest-authority rotation key, so nothing can nullify it",
			ErrInvalidChain, disputed.CID)
	}
	return forkKeys[:signerIdx], nil
}
