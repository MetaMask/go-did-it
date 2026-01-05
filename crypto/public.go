// Package crypto is a thin ergonomic layer on top of the normal golang crypto packages or `x/crypto`.
//
// It aims to solve the following problems with the standard crypto packages:
//   - different algorithms have different APIs and ergonomics, which makes it hard to use them interchangeably
//   - occasionally, it's quite hard to figure out how to do simple tasks (like encoding/decoding keys)
//   - it's still necessary to make some educated choices (e.g. which hash function to use for signatures)
//   - sometimes features are left out (e.g. ed25519 to X25519 for key exchange, secp256k1...)
//   - some hash functions are not available in the standard library with no easy way to extend it (e.g. KECCAK-256)
//
// To do so, this package provides and implements a set of shared interfaces for all algorithms. As not all algorithms
// support all features (e.g. RSA keys don't support key exchange), some interfaces are optionally implemented.
//
// An additional benefit of shared interfaces is that a shared test suite can be written to test all algorithms, which this
// package does.
package crypto

type PublicKey interface {
	// Equal returns true if other is the same PublicKey
	Equal(other PublicKey) bool

	// ToPublicKeyMultibase format the PublicKey into a string compatible with a PublicKeyMultibase field
	// in a DID Document.
	ToPublicKeyMultibase() string

	// ToX509DER serializes the PublicKey into the X.509 DER (binary) format.
	ToX509DER() []byte

	// ToX509PEM serializes the PublicKey into the X.509 PEM (string) format.
	ToX509PEM() string
}

type PublicKeyToBytes interface {
	PublicKey

	// ToBytes serializes the PublicKey into "raw bytes", without metadata or structure.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	ToBytes() []byte
}

type PublicKeySigningBytes interface {
	PublicKey

	// VerifyBytes checks a signature in the "raw bytes" format.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	VerifyBytes(message, signature []byte, opts ...SigningOption) bool
}

type PublicKeySigningASN1 interface {
	PublicKey

	// VerifyASN1 checks a signature in the ASN.1 format.
	VerifyASN1(message, signature []byte, opts ...SigningOption) bool
}
