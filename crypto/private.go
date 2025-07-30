package crypto

import "github.com/ucan-wg/go-varsig"

type PrivateKey interface {
	// Equal returns true if other is the same PrivateKey
	Equal(other PrivateKey) bool

	// Public returns the matching PublicKey.
	Public() PublicKey

	// ToPKCS8DER serializes the PrivateKey into the PKCS#8 DER (binary) format.
	ToPKCS8DER() []byte

	// ToPKCS8PEM serializes the PrivateKey into the PKCS#8 PEM (string) format.
	ToPKCS8PEM() string
}

type PrivateKeyToBytes interface {
	PrivateKey

	// ToBytes serializes the PrivateKey into "raw bytes", without metadata or structure.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	ToBytes() []byte
}

type PrivateKeySigningBytes interface {
	PrivateKey

	// Varsig returns the varsig.Varsig corresponding to the given parameters and private key.
	Varsig(opts ...SigningOption) varsig.Varsig

	// SignToBytes creates a signature in the "raw bytes" format.
	// This format can make some assumptions and may not be what you expect.
	// Ideally, this format is defined by the same specification as the underlying crypto scheme.
	SignToBytes(message []byte, opts ...SigningOption) ([]byte, error)
}

type PrivateKeySigningASN1 interface {
	PrivateKey

	// Varsig returns the varsig.Varsig corresponding to the given parameters and private key.
	Varsig(opts ...SigningOption) varsig.Varsig

	// SignToASN1 creates a signature in the ASN.1 format.
	SignToASN1(message []byte, opts ...SigningOption) ([]byte, error)
}

type PrivateKeyKeyExchange interface {
	PrivateKey

	// PublicKeyIsCompatible checks that the given PublicKey is compatible to perform key exchange.
	PublicKeyIsCompatible(remote PublicKey) bool

	// KeyExchange computes the shared key using the given PublicKey.
	KeyExchange(remote PublicKey) ([]byte, error)
}
