package did

import "fmt"

// Decoder errors
var (
	// ErrInvalidDid indicates that the DID supplied to the DID resolution function does not conform to valid syntax.
	ErrInvalidDid = fmt.Errorf("invalid DID")

	// ErrMethodNotSupported indicates that the DID method is not supported, or that the corresponding decoder
	// has not been registered properly.
	ErrMethodNotSupported = fmt.Errorf("DID method not supported")
)

// Resolver errors
var (
	// ErrNotFound indicates that the DID resolver was unable to find the DID document for the given DID.
	ErrNotFound = fmt.Errorf("did not found")
)
