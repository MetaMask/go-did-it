package crypto

type PublicKey interface {
	Equal(other PublicKey) bool

	ToBytes() []byte
	ToPublicKeyMultibase() string
	ToX509DER() []byte
	ToX509PEM() string
}

type PrivateKey interface {
	Equal(other PrivateKey) bool
	Public() PublicKey

	ToBytes() []byte
	ToPKCS8DER() []byte
	ToPKCS8PEM() string
}

type SigningPublicKey interface {
	PublicKey

	Verify(message, signature []byte) bool
}

type SigningPrivateKey interface {
	PrivateKey

	Sign(message []byte) ([]byte, error)
}

type KeyExchangePublicKey interface {
	PublicKey

	// PrivateKeyIsCompatible checks that the given PrivateKey is compatible to perform key exchange.
	PrivateKeyIsCompatible(local PrivateKey) bool

	// ECDH computes the shared key using the given PrivateKey.
	ECDH(local PrivateKey) ([]byte, error)
}
