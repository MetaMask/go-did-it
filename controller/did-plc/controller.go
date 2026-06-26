package did_plc

import (
	"context"
	"fmt"
)

// Controller is a handle for a specific DID within a Registry.
type Controller struct {
	registry *Registry
	didStr   string
}

// DidStr returns the did:plc string this controller manages.
func (c *Controller) DidStr() string { return c.didStr }

// Update fetches the current document state, passes it to fn, and submits the result.
func (c *Controller) Update(ctx context.Context, signer Signer, fn func(Op) (Op, error)) error {
	headCID, current, err := c.fetchHead(ctx)
	if err != nil {
		return err
	}
	next, err := fn(current)
	if err != nil {
		return err
	}
	signed, err := next.sign(c.registry, signer, &headCID)
	if err != nil {
		return err
	}
	return c.registry.submit(ctx, c.didStr, signed)
}

// Tombstone permanently deactivates the DID.
func (c *Controller) Tombstone(ctx context.Context, signer Signer) error {
	headCID, _, err := c.fetchHead(ctx)
	if err != nil {
		return err
	}
	signed, err := signTombstone(signer, headCID)
	if err != nil {
		return err
	}
	return c.registry.submit(ctx, c.didStr, signed)
}

// Recover forks the operation chain back to forkCID. It fetches the document
// state at that point, passes it to fn, and submits the result.
func (c *Controller) Recover(ctx context.Context, signer Signer, forkCID string, fn func(Op) (Op, error)) error {
	forkOp, err := c.fetchOpAtCID(ctx, forkCID)
	if err != nil {
		return err
	}
	next, err := fn(forkOp)
	if err != nil {
		return err
	}
	signed, err := next.sign(c.registry, signer, &forkCID)
	if err != nil {
		return err
	}
	return c.registry.submit(ctx, c.didStr, signed)
}

// Audit fetches and validates the full operation history of the DID.
func (c *Controller) Audit(ctx context.Context) ([]AuditEntry, error) {
	entries, err := c.registry.fetchAuditLog(ctx, c.didStr)
	if err != nil {
		return nil, err
	}
	if err := c.registry.validateChain(entries); err != nil {
		return nil, fmt.Errorf("chain validation failed: %w", err)
	}
	return entries, nil
}

// fetchHead returns the CID and document state of the latest non-nullified operation.
func (c *Controller) fetchHead(ctx context.Context) (string, Op, error) {
	entries, err := c.registry.fetchAuditLog(ctx, c.didStr)
	if err != nil {
		return "", Op{}, fmt.Errorf("fetching audit log: %w", err)
	}
	var headCID string
	var headOp *Op
	for i := range entries {
		if !entries[i].Nullified {
			headCID = entries[i].CID
			headOp = entries[i].Op
		}
	}
	if headCID == "" {
		return "", Op{}, fmt.Errorf("no valid operations found for %s", c.didStr)
	}
	if headOp == nil {
		return "", Op{}, fmt.Errorf("DID %s is tombstoned", c.didStr)
	}
	return headCID, *headOp, nil
}

// fetchOpAtCID finds and returns the document state at a specific CID in the audit log.
func (c *Controller) fetchOpAtCID(ctx context.Context, cid string) (Op, error) {
	entries, err := c.registry.fetchAuditLog(ctx, c.didStr)
	if err != nil {
		return Op{}, fmt.Errorf("fetching audit log: %w", err)
	}
	for _, e := range entries {
		if e.CID == cid {
			if e.Op == nil {
				return Op{}, nil
			}
			return *e.Op, nil
		}
	}
	return Op{}, fmt.Errorf("operation with CID %s not found for %s", cid, c.didStr)
}
