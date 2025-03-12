package did

import (
	"fmt"
	"strings"
	"sync"
)

// Decoder is a function decoding an identifier ("foo" in "did:example:foo") into a DID.
type Decoder func(identifier string) (DID, error)

var (
	decodersMu sync.RWMutex
	decoders   = map[string]Decoder{}
)

// RegisterMethod registers a DID decoder for a given DID method..
// Method must be the DID method (for example "key" in did:key).
func RegisterMethod(method string, decoder Decoder) {
	decodersMu.Lock()
	defer decodersMu.Unlock()
	if !checkMethod(method) {
		panic("invalid method")
	}
	if decoders[method] != nil {
		panic("did decoder already registered")
	}
	decoders[method] = decoder
}

// Parse returns the DID from the string representation or an error if
// the prefix and method are incorrect, if an unknown encryption algorithm
// is specified or if the method-specific-identifier's bytes don't
// represent a public key for the specified encryption algorithm.
func Parse(str string) (DID, error) {
	decodersMu.RLock()
	defer decodersMu.RUnlock()

	if !strings.HasPrefix(str, "did:") {
		return nil, fmt.Errorf("%w: must start with \"did:\"", ErrInvalidDid)
	}

	method, identifier, ok := strings.Cut(str[len("did:"):], ":")
	if !ok {
		return nil, fmt.Errorf("%w: must have a method and an identifier", ErrInvalidDid)
	}

	if !checkIdentifier(identifier) {
		return nil, fmt.Errorf("%w: invalid identifier characters", ErrInvalidDid)
	}

	decoder, ok := decoders[method]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotSupported, method)
	}

	return decoder(identifier)
}

// MustParse is like Parse but panics instead of returning an error.
func MustParse(str string) DID {
	did, err := Parse(str)
	if err != nil {
		panic(err)
	}
	return did
}

func checkMethod(method string) bool {
	if len(method) == 0 {
		return false
	}
	for _, char := range method {
		isAlpha := 'a' <= char && char <= 'z'
		isDigit := '0' <= char && char <= '9'
		if !isAlpha && !isDigit {
			return false
		}
	}
	return true
}

func checkIdentifier(identifier string) bool {
	if len(identifier) == 0 {
		return false
	}
	// TODO
	// for _, char := range identifier {
	//
	// }

	return true
}
