package crypto

import (
	"fmt"
	"sync"

	helpers "github.com/MetaMask/go-did-it/crypto/internal"
)

// KeyType describes how to decode keys of a single algorithm (and, for RSA, which key sizes to accept).
//
// It is the unit a KeySet is built from. Each crypto/<algo> package provides one through its
// KeyType() constructor (e.g. ed25519.KeyType(), rsa.KeyType(2048)), which is the only place that knows
// the algorithm's encoding details. Because the crypto package itself doesn't import any algorithm
// package, your binary only links the algorithms you actually name.
//
// The decode functions return a nil PublicKey/PrivateKey together with an error on failure; a nil
// function means that form is not supported for this algorithm (for example RSA has no raw private
// bytes form).
type KeyType struct {
	// Name is a human-readable identifier, used in error messages (e.g. "Ed25519", "RSA-2048").
	Name string
	// Code is the algorithm's multicodec code (the prefix in a publicKeyMultibase form). It is unique
	// within a KeySet; registering a KeyType whose code is already present replaces the previous one.
	Code uint64

	// DecodePublic decodes a public key from the body of its publicKeyMultibase form (the bytes
	// after the multicodec prefix). For most algorithms that body is the raw key material; for RSA
	// it is the PKCS#1 (RSAPublicKey) DER. It is also used by PublicKeyFromBytes.
	DecodePublic func(body []byte) (PublicKey, error)

	// Matches reports whether an already-decoded key belongs to this KeyType.
	// It is the inverse of DecodePublic: a type assertion plus any additional constraints
	// (e.g. RSA key size). Nil means a code match alone is sufficient.
	Matches func(key PublicKey) bool
}

// KeySet is a configured-once set of the key algorithms (and sizes) that decoding is allowed to
// accept. Build one with NewKeySet and pass it where you need explicit, isolated control; or use
// the package-level DefaultKeySet singleton (and the matching package-level functions) for the global,
// blank-import style.
//
// A KeySet is safe for concurrent use.
type KeySet struct {
	mu     sync.RWMutex
	byCode map[uint64]KeyType
}

// NewKeySet builds a KeySet accepting exactly the given key types.
func NewKeySet(keyTypes ...KeyType) *KeySet {
	ks := &KeySet{byCode: make(map[uint64]KeyType)}
	ks.Register(keyTypes...)
	return ks
}

// Register adds key types to the KeySet, replacing any already registered under the same code. It is
// safe to call concurrently; this is how the package-level DefaultKeySet is populated (directly, via
// Register, or via a blank import of a registering package such as crypto/all).
func (ks *KeySet) Register(keyTypes ...KeyType) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, kt := range keyTypes {
		ks.byCode[kt.Code] = kt
	}
}

// PublicKeyFromMultibase decodes a public key from its publicKeyMultibase form, accepting it only if
// its algorithm is in the KeySet.
func (ks *KeySet) PublicKeyFromMultibase(multibase string) (PublicKey, error) {
	code, body, err := helpers.PublicKeyMultibaseDecode(multibase)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	return ks.PublicKeyFromBytes(code, body)
}

// PublicKeyFromBytes decodes a public key from the body bytes of the given multicodec code, accepting
// it only if its algorithm is in the KeySet. For RSA the body is the PKCS#1 (RSAPublicKey) DER.
func (ks *KeySet) PublicKeyFromBytes(code uint64, body []byte) (PublicKey, error) {
	ks.mu.RLock()
	kt, ok := ks.byCode[code]
	ks.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unsupported key: multicodec code %#x not in key set", code)
	}
	if kt.DecodePublic == nil {
		return nil, fmt.Errorf("public key decoding not supported for multicodec code %#x", code)
	}
	return kt.DecodePublic(body)
}

// Accepts reports whether key's type (and, for constrained types like RSA, its parameters)
// are accepted by this KeySet. It uses the Matches predicate from the registered KeyType.
func (ks *KeySet) Accepts(key PublicKey) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for _, kt := range ks.byCode {
		if kt.Matches != nil && kt.Matches(key) {
			return true
		}
	}
	return false
}

// DefaultKeySet is the package-level KeySet used by the package-level decoding functions and, by default,
// by the verifier packages (did:key, the Multikey verification method, ...). It starts empty:
// register the algorithms you want with Register, or pull them all in for tests/tools with a blank
// import of crypto/all.
var DefaultKeySet = NewKeySet()

// Register adds key types to the DefaultKeySet KeySet.
func Register(keyTypes ...KeyType) { DefaultKeySet.Register(keyTypes...) }

// PublicKeyFromMultibase decodes a public key from its publicKeyMultibase form using the DefaultKeySet KeySet.
func PublicKeyFromMultibase(multibase string) (PublicKey, error) {
	return DefaultKeySet.PublicKeyFromMultibase(multibase)
}

// PublicKeyFromBytes decodes a public key from its body bytes using the DefaultKeySet KeySet.
func PublicKeyFromBytes(code uint64, body []byte) (PublicKey, error) {
	return DefaultKeySet.PublicKeyFromBytes(code, body)
}

// ToPub converts the result of a concrete public-key constructor (one returning a specific key type,
// as the crypto/<algo> packages do) to the PublicKey interface. It is a convenience for writing the
// decode functions of a KeyType:
//
//	DecodePublic: func(b []byte) (crypto.PublicKey, error) { return crypto.ToPub(PublicKeyFromBytes(b)) },
func ToPub[T PublicKey](k T, err error) (PublicKey, error) { return k, err }
