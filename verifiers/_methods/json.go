package methods

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
)

// FromJsonFunc decodes a verification method of a single type from JSON. ks is never nil.
// Implementations must decode any key material through ks (never by calling an algorithm
// package directly), so that disallowed algorithms are rejected before their key data is
// even parsed. The registry itself carries no policy: which method types are decodable is
// a format capability controlled by imports, while which key algorithms are accepted is
// controlled solely by ks.
type FromJsonFunc func(data []byte, ks *crypto.KeySet) (did.VerificationMethod, error)

// registry maps verification method types (e.g. "Multikey") to their decoding function.
// It is typically populated by the verification method packages' init(): importing a
// verification method package registers its types.
var (
	mu       sync.RWMutex
	registry = map[string]FromJsonFunc{}
)

// Register records the decoding function for a verification method type. It is safe to
// call concurrently.
func Register(vmType string, fn FromJsonFunc) {
	mu.Lock()
	defer mu.Unlock()
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

	mu.RLock()
	fn, ok := registry[aux.Type]
	empty := len(registry) == 0
	mu.RUnlock()
	if !ok {
		if empty {
			return nil, fmt.Errorf("unknown verification type: %s (no verification method type is registered: import the packages you support, or verifiers/_methods/all)", aux.Type)
		}
		return nil, fmt.Errorf("unknown verification type: %s", aux.Type)
	}

	return fn(data, ks)
}
