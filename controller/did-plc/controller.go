package didplcctl

import (
	"context"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it"
	didplc "github.com/MetaMask/go-did-it/verifiers/did-plc"
)

// Controller is a handle on a specific DID within a [Registry], through which operations
// on that DID are built, signed and submitted.
type Controller struct {
	registry *Registry
	did      didplc.DidPlc
}

// Did returns the DID this controller manages. Resolve it to a document with
// [did.DID.Document].
func (c *Controller) Did() did.DID { return c.did }

// DidStr returns the did:plc string this controller manages.
func (c *Controller) DidStr() string { return c.did.String() }

// Head is the state a new operation is built on: the DID's most recent operation and
// the document state it established.
type Head struct {
	// CID identifies the most recent operation, and becomes the prev of the next one.
	CID string
	// Op is the document state that operation established.
	Op Op

	// rotKeys is Op.RotationKeys in the form the signing and verification code needs: the
	// wire string to check a signer against, and the decoded key to check a signature with.
	rotKeys []rotationKey
}

// Head returns the DID's current state. How far the registry's account of that state is
// verified is set once per Registry by [WithChainVerification].
//
// It returns [ErrDeactivated] if the DID has been tombstoned.
func (c *Controller) Head(ctx context.Context) (Head, error) {
	didStr := c.DidStr()
	if c.registry.verification == VerifyHeadOnly {
		p, err := c.registry.fetchLastOp(ctx, didStr)
		if err != nil {
			return Head{}, err
		}
		if p.isTombstone() {
			return Head{}, ErrDeactivated
		}
		cid, err := computeCID(p.signed)
		if err != nil {
			return Head{}, err
		}
		return Head{CID: cid, Op: *p.op, rotKeys: p.rotKeys}, nil
	}
	ops, err := c.registry.fetchOperationLog(ctx, didStr)
	if err != nil {
		return Head{}, err
	}
	head, err := validateOperationLog(didStr, ops)
	switch {
	case errors.Is(err, ErrDeactivated):
		// A status, not a validation failure: report it plainly.
		return Head{}, err
	case err != nil:
		return Head{}, fmt.Errorf("validating operation log of %s: %w", didStr, err)
	}
	return head, nil
}

// Update fetches the current state, passes it to fn, and submits the result as the next
// operation. signer must hold one of the current state's rotation keys.
//
// The fetch and the submission are two requests, so an operation submitted by someone
// else in between makes the registry reject this one with a [RegistryError]; calling
// Update again picks up the new state.
func (c *Controller) Update(ctx context.Context, signer Signer, fn func(Op) (Op, error)) error {
	head, err := c.Head(ctx)
	if err != nil {
		return err
	}
	next, err := fn(head.Op)
	if err != nil {
		return err
	}
	prepared, err := c.registry.signUpdate(next, signer, head.CID, head.rotKeys)
	if err != nil {
		return err
	}
	return c.registry.submit(ctx, c.DidStr(), prepared.jsonBytes)
}

// Tombstone permanently deactivates the DID. signer must hold one of the current state's
// rotation keys.
//
// The operation is itself subject to the recovery window, so a higher-authority rotation
// key can undo it with [Controller.Recover] for 72 hours.
func (c *Controller) Tombstone(ctx context.Context, signer Signer) error {
	head, err := c.Head(ctx)
	if err != nil {
		return err
	}
	prepared, err := signTombstone(signer, head.CID, head.rotKeys)
	if err != nil {
		return err
	}
	return c.registry.submit(ctx, c.DidStr(), prepared.jsonBytes)
}

// Recover forks the operation chain back to forkCID, nullifying everything the registry
// has accepted since. It fetches the state as of that point, passes it to fn, and
// submits the result.
//
// This is only open to a rotation key outranking the one that signed the first operation
// being nullified, and only within 72 hours of that operation; both are checked locally
// before signing. Obtain forkCID from [Controller.Audit].
//
// Recovery needs the nullified forks and the registry's timestamps, so it always reads
// the full audit log; [WithChainVerification] decides whether that log is validated
// first.
func (c *Controller) Recover(ctx context.Context, signer Signer, forkCID string, fn func(Op) (Op, error)) error {
	didStr := c.DidStr()
	entries, err := c.registry.fetchAuditLog(ctx, didStr)
	if err != nil {
		return err
	}
	if c.registry.verification != VerifyHeadOnly {
		if err := validateAuditLog(didStr, entries); err != nil {
			return fmt.Errorf("validating audit log of %s: %w", didStr, err)
		}
	}
	base, authorized, err := recoveryAuthority(entries, forkCID)
	if err != nil {
		return err
	}
	next, err := fn(*base)
	if err != nil {
		return err
	}
	prepared, err := c.registry.signUpdate(next, signer, forkCID, authorized)
	if err != nil {
		return err
	}
	return c.registry.submit(ctx, didStr, prepared.jsonBytes)
}

// Audit fetches the full operation history of the DID and validates it, forks included:
// the DID is the hash of the genesis operation, every operation points at its predecessor
// and is signed by one of that predecessor's rotation keys, every operation that nullified
// others was signed by a rotation key outranking the one that signed the first operation
// it nullified and landed within the 72 hour recovery window, and the nullified flags the
// registry reported match a replay of the log.
//
// Unlike the other methods it always validates in full, whatever [WithChainVerification]
// says: reporting the history is the point of it.
//
// The registry's timestamps are not covered by any signature, so the recovery window and
// ordering checks hold the registry to its own account of events rather than proving
// anything on their own.
func (c *Controller) Audit(ctx context.Context) ([]AuditEntry, error) {
	didStr := c.DidStr()
	entries, err := c.registry.fetchAuditLog(ctx, didStr)
	if err != nil {
		return nil, err
	}
	if err := validateAuditLog(didStr, entries); err != nil {
		return nil, fmt.Errorf("validating audit log of %s: %w", didStr, err)
	}
	return entries, nil
}
