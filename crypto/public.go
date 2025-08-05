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
