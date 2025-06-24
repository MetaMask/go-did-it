package crypto

type PublicKey interface {
	// Equal returns true if other is the same PublicKey
	Equal(other PublicKey) bool

	// ToBytes serializes the PublicKey into "raw bytes", without metadata or structure.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	ToBytes() []byte

	// ToPublicKeyMultibase format the PublicKey into a string compatible with a PublicKeyMultibase field
	// in a DID Document.
	ToPublicKeyMultibase() string

	// ToX509DER serializes the PublicKey into the X.509 DER (binary) format.
	ToX509DER() []byte

	// ToX509PEM serializes the PublicKey into the X.509 PEM (string) format.
	ToX509PEM() string
}

type PrivateKey interface {
	// Equal returns true if other is the same PrivateKey
	Equal(other PrivateKey) bool

	// Public returns the matching PublicKey.
	Public() PublicKey

	// ToBytes serializes the PrivateKey into "raw bytes", without metadata or structure.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	ToBytes() []byte

	// ToPKCS8DER serializes the PrivateKey into the PKCS#8 DER (binary) format.
	ToPKCS8DER() []byte

	// ToPKCS8PEM serializes the PrivateKey into the PKCS#8 PEM (string) format.
	ToPKCS8PEM() string
}

type SigningPublicKey interface {
	PublicKey

	// VerifyBytes checks a signature in the "raw bytes" format.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	VerifyBytes(message, signature []byte) bool

	// VerifyASN1 checks a signature in the ASN.1 format.
	VerifyASN1(message, signature []byte) bool
}

type SigningPrivateKey interface {
	PrivateKey

	// SignToBytes creates a signature in the "raw bytes" format.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	SignToBytes(message []byte) ([]byte, error)

	// SignToASN1 creates a signature in the ASN.1 format.
	SignToASN1(message []byte) ([]byte, error)
}

type KeyExchangePrivateKey interface {
	PrivateKey

	// PublicKeyIsCompatible checks that the given PublicKey is compatible to perform key exchange.
	PublicKeyIsCompatible(remote PublicKey) bool

	// KeyExchange computes the shared key using the given PublicKey.
	KeyExchange(remote PublicKey) ([]byte, error)
}
