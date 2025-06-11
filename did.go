package did

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

const JsonLdContext = "https://www.w3.org/ns/did/v1"

// Decoder is a function decoding a DID string representation ("did:example:foo") into a DID.
type Decoder func(didStr string) (DID, error)

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
func Parse(didStr string) (DID, error) {
	decodersMu.RLock()
	defer decodersMu.RUnlock()

	if !strings.HasPrefix(didStr, "did:") {
		return nil, fmt.Errorf("%w: must start with \"did:\"", ErrInvalidDid)
	}

	method, suffix, ok := strings.Cut(didStr[len("did:"):], ":")
	if !ok {
		return nil, fmt.Errorf("%w: must have a method and an identifier", ErrInvalidDid)
	}

	if !checkMethodSpecificId(suffix) {
		return nil, fmt.Errorf("%w: invalid identifier characters", ErrInvalidDid)
	}

	decoder, ok := decoders[method]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotSupported, method)
	}

	return decoder(didStr)
}

// MustParse is like Parse but panics instead of returning an error.
func MustParse(didStr string) DID {
	did, err := Parse(didStr)
	if err != nil {
		panic(err)
	}
	return did
}

// HasValidDIDSyntax tells if the given string representation conforms to DID syntax.
// This does NOT verify that the method is supported by this library.
func HasValidDIDSyntax(didStr string) bool {
	if !strings.HasPrefix(didStr, "did:") {
		return false
	}
	method, suffix, ok := strings.Cut(didStr[len("did:"):], ":")
	if !ok {
		return false
	}
	return checkMethod(method) && checkMethodSpecificId(suffix)
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

func checkMethodSpecificId(suffix string) bool {
	if len(suffix) == 0 {
		return false
	}

	segments := strings.Split(suffix, ":")
	for i, segment := range segments {
		if i == len(segments)-1 && len(segment) == 0 {
			// last segment can't be empty
			return false
		}
		var percentExpected int
		for _, char := range segment {
			if percentExpected > 0 {
				switch {
				case char >= '0' && char <= '9':
					percentExpected--
				case char >= 'a' && char <= 'f':
					percentExpected--
				case char >= 'A' && char <= 'F':
					percentExpected--
				default:
					return false
				}
			}
			switch {
			case char >= 'a' && char <= 'z': // nothing to do
			case char >= 'A' && char <= 'Z': // nothing to do
			case char >= '0' && char <= '9': // nothing to do
			case char == '.': // nothing to do
			case char == '-': // nothing to do
			case char == '_': // nothing to do
			case char == '%':
				percentExpected = 2
			default:
				return false
			}
		}
		if percentExpected > 0 {
			// unfinished percent encoding
			return false
		}
	}

	return true
}

// HasValidDidUrlSyntax tells if the given string representation conforms to DID URL syntax.
// This does NOT verify that the method is supported by this library.
func HasValidDidUrlSyntax(didUrlStr string) bool {
	cutPos := strings.IndexAny(didUrlStr, "/#?")
	if cutPos == -1 {
		return HasValidDIDSyntax(didUrlStr)
	}

	base, rest := didUrlStr[:cutPos], didUrlStr[cutPos+1:]
	if HasValidDIDSyntax(base) == false {
		return false
	}

	_, err := url.Parse("example.com" + rest)
	return err == nil
}

var (
	decodersMu sync.RWMutex
	decoders   = map[string]Decoder{}
)
