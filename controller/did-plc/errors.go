package didplcctl

import (
	"errors"
)

// ErrDeactivated reports that the DID has been tombstoned, and so has no current state
// to build an operation on.
var ErrDeactivated = errors.New("did:plc DID is deactivated")

// ErrInvalidChain reports that the operation log served by the registry failed
// validation. Every chain validation failure wraps it.
var ErrInvalidChain = errors.New("invalid did:plc operation chain")
