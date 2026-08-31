package crypto

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"

	helpers "github.com/MetaMask/go-did-it/crypto/internal"
)

// ErrKeyNotAccepted reports a policy rejection: the key is well-formed, but its algorithm (or its
// parameters, like the RSA modulus size) is not accepted by the KeyPolicy.
var ErrKeyNotAccepted = errors.New("key type not accepted by the key policy")

// emptyPolicyHint points at the likely cause when a KeyPolicy rejects everything: DefaultKeyPolicy starts
// empty and nothing was registered.
const emptyPolicyHint = "the key policy is empty (register algorithms with Register, or import crypto/all)"

// ErrInvalidKey reports malformed key data that failed to decode.
var ErrInvalidKey = errors.New("invalid key data")

// KeyType describes how to decode keys of a single algorithm (and, for RSA, which key sizes to accept).
//
// It is the unit a KeyPolicy is built from. Each crypto/<algo> package provides one through its
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
	// within a KeyPolicy; registering a KeyType whose code is already present replaces the previous one.
	Code uint64

	// DecodePublic decodes a public key from the body of its publicKeyMultibase form (the bytes
	// after the multicodec prefix). For most algorithms that body is the raw key material; for RSA
	// it is the PKCS#1 (RSAPublicKey) DER. It is also used by PublicKeyFromBytes.
	DecodePublic func(body []byte) (PublicKey, error)

	// Matches reports whether an already-decoded key belongs to this KeyType.
	// It is the inverse of DecodePublic: a type assertion plus any additional constraints
	// (e.g. RSA key size). It is required for the key policy acceptance checks (Accepts, CheckKey):
	// a KeyType with a nil Matches is never accepted by them.
	Matches func(key PublicKey) bool

	// Wrap converts an already-parsed public key object into this KeyType's PublicKey. It is the
	// inverse of the concrete types' Unwrap: it accepts a standard library key (ed25519.PublicKey,
	// *ecdsa.PublicKey, *rsa.PublicKey, *ecdh.PublicKey) or, for algorithms without a standard
	// library type, the underlying library's type (e.g. dcrd's *secp256k1.PublicKey). The boolean
	// reports whether the key belongs to this KeyType at all; an error means the key belongs here
	// but is rejected (for example by the RSA size policy). Nil means wrapping is not supported
	// for this algorithm.
	Wrap func(key any) (PublicKey, bool, error)

	// JwkKty and JwkCrv identify the algorithm in the JWK format (RFC 7517/7518): the "kty" and
	// "crv" members, e.g. "OKP"/"Ed25519", "EC"/"P-256". JwkCrv is empty for RSA.
	JwkKty string
	JwkCrv string

	// DecodeJwkPublic decodes a public key from the base64url-decoded JWK parameters
	// (e.g. params["x"], params["y"] for EC, params["n"], params["e"] for RSA).
	// Nil means JWK public key decoding is not supported for this algorithm.
	DecodeJwkPublic func(params map[string][]byte) (PublicKey, error)

	// DecodeJwkPrivate decodes a private key from the base64url-decoded JWK parameters
	// (e.g. params["d"], and for RSA also params["n"], params["e"], params["p"], params["q"]).
	// Nil means JWK private key decoding is not supported for this algorithm.
	DecodeJwkPrivate func(params map[string][]byte) (PrivateKey, error)
}

// KeyPolicy is a configured-once set of the key algorithms (and sizes) that decoding is allowed to
// accept. Build one with NewKeyPolicy and pass it where you need explicit, isolated control; or use
// the package-level DefaultKeyPolicy singleton (and the matching package-level functions) for the global,
// blank-import style.
//
// A KeyPolicy is safe for concurrent use.
type KeyPolicy struct {
	mu     sync.RWMutex
	byCode map[uint64]KeyType
}

// NewKeyPolicy builds a KeyPolicy accepting exactly the given key types.
func NewKeyPolicy(keyTypes ...KeyType) *KeyPolicy {
	kp := &KeyPolicy{byCode: make(map[uint64]KeyType)}
	kp.Register(keyTypes...)
	return kp
}

// Register adds key types to the KeyPolicy, replacing any already registered under the same code. It is
// safe to call concurrently; this is how the package-level DefaultKeyPolicy is populated (directly, via
// Register, or via a blank import of a registering package such as crypto/all).
func (kp *KeyPolicy) Register(keyTypes ...KeyType) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	for _, kt := range keyTypes {
		kp.byCode[kt.Code] = kt
	}
}

// PublicKeyFromMultibase decodes a public key from its publicKeyMultibase form, accepting it only if
// its algorithm is in the KeyPolicy.
func (kp *KeyPolicy) PublicKeyFromMultibase(multibase string) (PublicKey, error) {
	code, body, err := helpers.PublicKeyMultibaseDecode(multibase)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid publicKeyMultibase: %w", ErrInvalidKey, err)
	}
	return kp.PublicKeyFromBytes(code, body)
}

// PublicKeyFromBytes decodes a public key from the body bytes of the given multicodec code, accepting
// it only if its algorithm is in the KeyPolicy. For RSA the body is the PKCS#1 (RSAPublicKey) DER.
func (kp *KeyPolicy) PublicKeyFromBytes(code uint64, body []byte) (PublicKey, error) {
	kp.mu.RLock()
	kt, ok := kp.byCode[code]
	empty := len(kp.byCode) == 0
	kp.mu.RUnlock()

	if !ok {
		if empty {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotAccepted, emptyPolicyHint)
		}
		return nil, fmt.Errorf("%w: multicodec code %#x not in key policy", ErrKeyNotAccepted, code)
	}
	if kt.DecodePublic == nil {
		return nil, fmt.Errorf("%w: public key decoding not supported for %s", ErrKeyNotAccepted, kt.Name)
	}
	pub, err := kt.DecodePublic(body)
	if err != nil {
		if errors.Is(err, ErrKeyNotAccepted) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return pub, nil
}

// WrapPublicKey converts an already-parsed public key object (see KeyType.Wrap) into the
// corresponding PublicKey, accepting it only if its algorithm is in the KeyPolicy.
func (kp *KeyPolicy) WrapPublicKey(key any) (PublicKey, error) {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	for _, kt := range kp.byCode {
		if kt.Wrap == nil {
			continue
		}
		pub, ok, err := kt.Wrap(key)
		if !ok {
			continue
		}
		if err != nil {
			// Same split as PublicKeyFromBytes: a policy rejection stays ErrKeyNotAccepted,
			// anything else is malformed key data.
			if errors.Is(err, ErrKeyNotAccepted) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return pub, nil
	}
	if len(kp.byCode) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotAccepted, emptyPolicyHint)
	}
	return nil, fmt.Errorf("%w: no key type in the key policy matches %T", ErrKeyNotAccepted, key)
}

// KeyTypeForJwk returns the KeyType registered for the given JWK "kty"/"crv" pair
// (crv is empty for RSA), or false if none matches.
func (kp *KeyPolicy) KeyTypeForJwk(kty, crv string) (KeyType, bool) {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	for _, kt := range kp.byCode {
		if kt.JwkKty != "" && kt.JwkKty == kty && kt.JwkCrv == crv {
			return kt, true
		}
	}
	return KeyType{}, false
}

// KeyTypes returns the key types registered in the KeyPolicy, sorted by multicodec code.
func (kp *KeyPolicy) KeyTypes() []KeyType {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	res := make([]KeyType, 0, len(kp.byCode))
	for _, kt := range kp.byCode {
		res = append(res, kt)
	}
	slices.SortFunc(res, func(a, b KeyType) int { return cmp.Compare(a.Code, b.Code) })
	return res
}

// Accepts reports whether key's type (and, for constrained types like RSA, its parameters)
// are accepted by this KeyPolicy. It uses the Matches predicate from the registered KeyType.
func (kp *KeyPolicy) Accepts(key PublicKey) bool {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	for _, kt := range kp.byCode {
		if kt.Matches != nil && kt.Matches(key) {
			return true
		}
	}
	return false
}

// CheckKey returns nil if key is accepted by the KeyPolicy (see Accepts), or an error wrapping
// ErrKeyNotAccepted otherwise.
func (kp *KeyPolicy) CheckKey(key PublicKey) error {
	if kp.Accepts(key) {
		return nil
	}
	kp.mu.RLock()
	empty := len(kp.byCode) == 0
	kp.mu.RUnlock()
	if empty {
		return fmt.Errorf("%w: %s", ErrKeyNotAccepted, emptyPolicyHint)
	}
	return fmt.Errorf("%w: %T", ErrKeyNotAccepted, key)
}

// DefaultKeyPolicy is the package-level KeyPolicy used by the package-level decoding functions and, by default,
// by the verifier packages (did:key, the Multikey verification method, ...). It starts empty:
// register the algorithms you want with Register, or pull them all in for tests/tools with a blank
// import of crypto/all.
var DefaultKeyPolicy = NewKeyPolicy()

// Register adds key types to the DefaultKeyPolicy.
func Register(keyTypes ...KeyType) { DefaultKeyPolicy.Register(keyTypes...) }

// PublicKeyFromMultibase decodes a public key from its publicKeyMultibase form using the DefaultKeyPolicy.
func PublicKeyFromMultibase(multibase string) (PublicKey, error) {
	return DefaultKeyPolicy.PublicKeyFromMultibase(multibase)
}

// PublicKeyFromBytes decodes a public key from its body bytes using the DefaultKeyPolicy.
func PublicKeyFromBytes(code uint64, body []byte) (PublicKey, error) {
	return DefaultKeyPolicy.PublicKeyFromBytes(code, body)
}

// WrapPublicKey converts an already-parsed public key object using the DefaultKeyPolicy.
func WrapPublicKey(key any) (PublicKey, error) {
	return DefaultKeyPolicy.WrapPublicKey(key)
}

// KeyTypes returns the key types registered in the DefaultKeyPolicy, sorted by multicodec code.
func KeyTypes() []KeyType {
	return DefaultKeyPolicy.KeyTypes()
}

// ToPub converts the result of a concrete public-key constructor (one returning a specific key type,
// as the crypto/<algo> packages do) to the PublicKey interface. It is a convenience for writing the
// decode functions of a KeyType:
//
//	DecodePublic: func(b []byte) (crypto.PublicKey, error) { return crypto.ToPub(PublicKeyFromBytes(b)) },
func ToPub[T PublicKey](k T, err error) (PublicKey, error) { return k, err }

// ToPriv converts the result of a concrete private-key constructor (one returning a specific key
// type, as the crypto/<algo> packages do) to the PrivateKey interface. It is a convenience for
// writing the decode functions of a KeyType, like ToPub.
func ToPriv[T PrivateKey](k T, err error) (PrivateKey, error) { return k, err }

// ToWrap converts the result of a concrete WrapPublicKey constructor (one returning a specific key
// type, as the crypto/<algo> packages do) to the PublicKey interface. It is a convenience for
// writing the Wrap function of a KeyType:
//
//	Wrap: func(key any) (crypto.PublicKey, bool, error) { return crypto.ToWrap(WrapPublicKey(key)) },
func ToWrap[T PublicKey](k T, ok bool, err error) (PublicKey, bool, error) { return k, ok, err }
