package didplcctl

import "time"

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
	// Op is the document state this operation established, or nil for a tombstone.
	Op *Op

	prepared *preparedOp
}
