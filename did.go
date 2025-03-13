package did

import (
	"fmt"
	"strings"
	"sync"
)

const JsonLdContext = "https://www.w3.org/ns/did/v1"

// Decoder is a function decoding a DID string representation ("did:example:foo") into a DID.
type Decoder func(identifier string) (DID, error)

// RegisterMethod registers a DID decoder for a given DID method.
// Method must be the DID method (for example, "key" in did:key).
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

// Parse attempts to decode a DID from its string representation.
func Parse(identifier string) (DID, error) {
	decodersMu.RLock()
	defer decodersMu.RUnlock()

	if !strings.HasPrefix(identifier, "did:") {
		return nil, fmt.Errorf("%w: must start with \"did:\"", ErrInvalidDid)
	}

	method, suffix, ok := strings.Cut(identifier[len("did:"):], ":")
	if !ok {
		return nil, fmt.Errorf("%w: must have a method and an identifier", ErrInvalidDid)
	}

	if !checkSuffix(suffix) {
		return nil, fmt.Errorf("%w: invalid identifier characters", ErrInvalidDid)
	}

	decoder, ok := decoders[method]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotSupported, method)
	}

	return decoder(identifier)
}

// MustParse is like Parse but panics instead of returning an error.
func MustParse(identifier string) DID {
	did, err := Parse(identifier)
	if err != nil {
		panic(err)
	}
	return did
}

// HasValidSyntax tells if the given string representation conforms to DID syntax.
// This does NOT verify that the method is supported by this library.
func HasValidSyntax(identifier string) bool {
	if !strings.HasPrefix(identifier, "did:") {
		return false
	}
	method, suffix, ok := strings.Cut(identifier[len("did:"):], ":")
	if !ok {
		return false
	}
	return checkMethod(method) && checkSuffix(suffix)
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

func checkSuffix(suffix string) bool {
	if len(suffix) == 0 {
		return false
	}
	// TODO
	// for _, char := range suffix {
	//
	// }

	return true
}

var (
	decodersMu sync.RWMutex
	decoders   = map[string]Decoder{}
)
