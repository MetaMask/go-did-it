package methods

import (
	"encoding/json"
	"fmt"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
)

// FromJsonFunc decodes a verification method of a single type from JSON, using ks to
// decode and accept keys. ks is never nil.
type FromJsonFunc func(data []byte, ks *crypto.KeySet) (did.VerificationMethod, error)

// registry maps verification method types (e.g. "Multikey") to their decoding function.
// It is populated by the verification method packages' init(), so it is effectively
// read-only afterward: importing a verification method package registers its types.
var registry = map[string]FromJsonFunc{}

// Register records the decoding function for a verification method type.
func Register(vmType string, fn FromJsonFunc) {
	registry[vmType] = fn
}

// UnmarshalJSON decodes a verification method from JSON. Only verification method types
// registered with Register (done by importing their package) can be decoded. The key is
// decoded and accepted according to ks; if ks is nil, crypto.DefaultKeySet is used.
func UnmarshalJSON(data []byte, ks *crypto.KeySet) (did.VerificationMethod, error) {
	if ks == nil {
		ks = crypto.DefaultKeySet
	}

	var aux struct {
		Type string
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, err
	}

	fn, ok := registry[aux.Type]
	if !ok {
		return nil, fmt.Errorf("unknown verification type: %s", aux.Type)
	}

	res, err := fn(data, ks)
	if err != nil {
		return nil, err
	}

	// Enforce the key set on the decoded key, when the verification method holds one.
	if wk, ok := res.(interface{ PublicKey() crypto.PublicKey }); ok {
		if key := wk.PublicKey(); key != nil {
			if err := ks.CheckKey(key); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}
