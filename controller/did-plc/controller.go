package didplcctl

import (
	"context"
	"fmt"

	"github.com/MetaMask/go-did-it"
	didplc "github.com/MetaMask/go-did-it/verifiers/did-plc"
)

// The public API. Each method is one move on the operation log described in the package
// doc:
//
//	Head        read the live path's last operation, and the state it established
//	Update      append an operation to the live path
//	Recover     fork the log at an earlier operation, nullifying the tail
//	Tombstone   append an operation that ends the DID
//	Audit       report the whole tree, forks included, after replaying it
//
// Update, Recover and Tombstone each read the current state first, so each is two round
// trips and neither is atomic; a competing operation in between makes the registry reject
// the second one.

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

// Head returns the DID's current state. By default that is the registry's report of it,
// taken on trust; [WithFullChainVerification] makes it a state replayed from the genesis
// operation instead.
//
// It returns [ErrDeactivated] if the DID has been tombstoned.
func (c *Controller) Head(ctx context.Context) (Head, error) {
	didStr := c.DidStr()
	if !c.registry.fullVerification {
		p, err := c.registry.fetchLastOp(ctx, didStr)
		if err != nil {
			return Head{}, err
		}
		if p.isTombstone() {
			return Head{}, ErrDeactivated
		}
		cid, err := p.cid()
		if err != nil {
			return Head{}, err
		}
		return Head{CID: cid, State: *p.state, rotKeys: p.rotKeys}, nil
	}
	history, err := c.registry.fetchAuditLog(ctx, didStr)
	if err != nil {
		return Head{}, err
	}
	if err := history.validate(didStr); err != nil {
		return Head{}, fmt.Errorf("validating history of %s: %w", didStr, err)
	}
	// head reports ErrDeactivated plainly: it is a status, not a validation failure.
	return history.head()
}

// Update fetches the current state, passes it to fn, and submits the result as the next
// operation. signer must hold one of the current state's rotation keys.
//
// The fetch and the submission are two requests, so an operation submitted by someone
// else in between makes the registry reject this one with a [RegistryError]; calling
// Update again picks up the new state.
func (c *Controller) Update(ctx context.Context, signer Signer, fn func(State) (State, error)) error {
	head, err := c.Head(ctx)
	if err != nil {
		return err
	}
	next, err := fn(head.State)
	if err != nil {
		return err
	}
	prepared, err := c.registry.codec.signUpdate(next, signer, head.CID, head.rotKeys)
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
// the DID's full history; [WithFullChainVerification] decides whether that history is
// replayed and checked first.
func (c *Controller) Recover(ctx context.Context, signer Signer, forkCID string, fn func(State) (State, error)) error {
	didStr := c.DidStr()
	history, err := c.registry.fetchAuditLog(ctx, didStr)
	if err != nil {
		return err
	}
	if c.registry.fullVerification {
		if err := history.validate(didStr); err != nil {
			return fmt.Errorf("validating history of %s: %w", didStr, err)
		}
	}
	base, authorized, err := history.recoveryAuthority(forkCID)
	if err != nil {
		return err
	}
	next, err := fn(*base)
	if err != nil {
		return err
	}
	prepared, err := c.registry.codec.signUpdate(next, signer, forkCID, authorized)
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
// Unlike the other methods it always validates in full, whatever
// [WithFullChainVerification] says: reporting the history is the point of it.
//
// The registry's timestamps are not covered by any signature, so the recovery window and
// ordering checks hold the registry to its own account of events rather than proving
// anything on their own.
func (c *Controller) Audit(ctx context.Context) ([]AuditEntry, error) {
	didStr := c.DidStr()
	history, err := c.registry.fetchAuditLog(ctx, didStr)
	if err != nil {
		return nil, err
	}
	if err := history.validate(didStr); err != nil {
		return nil, fmt.Errorf("validating history of %s: %w", didStr, err)
	}
	return history, nil
}
