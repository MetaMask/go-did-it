package secp256k1

import (
	"encoding/asn1"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	// PublicKeyBytesSize is the size, in bytes, of public keys in raw bytes.
	PublicKeyBytesSize = secp256k1.PubKeyBytesLenCompressed
	// PrivateKeyBytesSize is the size, in bytes, of private keys in raw bytes.
	PrivateKeyBytesSize = secp256k1.PrivKeyBytesLen
	// SignatureBytesSize is the size, in bytes, of signatures in raw bytes.
	SignatureBytesSize = 64

	MultibaseCode = uint64(0xe7)

	// coordinateSize is the size, in bytes, of one coordinate in the elliptic curve.
	coordinateSize = 32
)

func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	pub := priv.PubKey()
	return &PublicKey{k: pub}, &PrivateKey{k: priv}, nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)

var (
	// Elliptic curve public key (OID: 1.2.840.10045.2.1)
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// Curve is secp256k1 (OID: 1.3.132.0.10)
	oidSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)
