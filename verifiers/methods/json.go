package methods

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
)

// ErrDirectUnmarshal is returned by the UnmarshalJSON method of every verification method type.
// Those methods exist only to fail closed: encoding/json cannot supply the crypto.KeyPolicy that
// decoding key material requires, and without them json.Unmarshal would silently succeed and leave
// a zero-value verification method (the struct fields are unexported, so there is nothing to fill).
// Decode through the per-type FromJSON functions or through UnmarshalJSON in this package instead.
var ErrDirectUnmarshal = errors.New("a verification method cannot be decoded with encoding/json: it needs a crypto.KeyPolicy to control which key algorithms are accepted")

// FromJsonFunc decodes a verification method of a single type from JSON. kp is never nil.
// Implementations must decode any key material through kp (never by calling an algorithm
// package directly), so that disallowed algorithms are rejected before their key data is
// even parsed. The registry itself carries no policy: which method types are decodable is
// a format capability controlled by imports, while which key algorithms are accepted is
// controlled solely by kp.
type FromJsonFunc func(data []byte, kp *crypto.KeyPolicy) (did.VerificationMethod, error)

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
// decoded and accepted according to kp; if kp is nil, crypto.DefaultKeyPolicy is used.
func UnmarshalJSON(data []byte, kp *crypto.KeyPolicy) (did.VerificationMethod, error) {
	if kp == nil {
		kp = crypto.DefaultKeyPolicy
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
			return nil, fmt.Errorf("unknown verification type: %s (no verification method type is registered: import the packages you support, or verifiers/methods/all)", aux.Type)
		}
		return nil, fmt.Errorf("unknown verification type: %s", aux.Type)
	}

	return fn(data, kp)
}
