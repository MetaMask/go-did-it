package secp256k1

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/MetaMask/go-did-it/crypto"
)

var _ crypto.PrivateKeySigningBytes = &PrivateKey{}
var _ crypto.PrivateKeySigningASN1 = &PrivateKey{}
var _ crypto.PrivateKeyKeyExchange = &PrivateKey{}

type PrivateKey struct {
	k *secp256k1.PrivateKey
}

// PrivateKeyFromBytes converts a serialized public key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyBytesSize {
		return nil, fmt.Errorf("invalid secp256k1 private key size")
	}
	return &PrivateKey{k: secp256k1.PrivKeyFromBytes(b)}, nil
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (*PrivateKey, error) {
	// Parse the PKCS#8 structure
	var pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(bytes, &pkcs8); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 structure: %w", err)
	}

	// Check if this is an Elliptic curve public key (OID: 1.2.840.10045.2.1)
	if !pkcs8.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, fmt.Errorf("not an EC private key, got OID: %v", pkcs8.Algo.Algorithm)
	}

	// Extract the curve OID from parameters
	var namedCurveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(pkcs8.Algo.Parameters.FullBytes, &namedCurveOID); err != nil {
		return nil, fmt.Errorf("failed to parse curve parameters: %w", err)
	}

	// Check if the curve is secp256k1 (OID: 1.3.132.0.10)
	if !namedCurveOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf("unsupported curve, expected secp256k1 (1.3.132.0.10), got: %v", namedCurveOID)
	}

	// Parse the EC private key structure (RFC 5915)
	var ecPrivKey struct {
		Version    int
		PrivateKey []byte
		PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
	}

	if _, err := asn1.Unmarshal(pkcs8.PrivateKey, &ecPrivKey); err != nil {
		return nil, fmt.Errorf("failed to parse alliptic curve private key: %w", err)
	}

	// Validate the EC private key version
	if ecPrivKey.Version != 1 {
		return nil, fmt.Errorf("unsupported EC private key version: %d", ecPrivKey.Version)
	}

	// Validate private key length
	if len(ecPrivKey.PrivateKey) != PrivateKeyBytesSize {
		return nil, fmt.Errorf("invalid secp256k1 private key length: %d, expected %d", len(ecPrivKey.PrivateKey), PrivateKeyBytesSize)
	}

	// Create the secp256k1 private key
	privKeySecp256k1 := secp256k1.PrivKeyFromBytes(ecPrivKey.PrivateKey)

	return &PrivateKey{k: privKeySecp256k1}, nil
}

// PrivateKeyFromPKCS8PEM decodes an PKCS#8 PEM (string) encoded private key.
func PrivateKeyFromPKCS8PEM(str string) (*PrivateKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPrivBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PrivateKeyFromPKCS8DER(block.Bytes)
}

func (p *PrivateKey) Equal(other crypto.PrivateKey) bool {
	if other, ok := other.(*PrivateKey); ok {
		return p.k.PubKey().IsEqual(other.k.PubKey())
	}
	return false
}

func (p *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{k: p.k.PubKey()}
}

func (p *PrivateKey) ToBytes() []byte {
	return p.k.Serialize()
}

func (p *PrivateKey) ToPKCS8DER() []byte {
	pubkeyBytes := p.k.PubKey().SerializeUncompressed()

	// Create the EC private key structure
	// This follows RFC 5915 format for EC private keys
	ecPrivateKey := struct {
		Version    int
		PrivateKey []byte
		Parameters asn1.RawValue  `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
	}{
		Version:    1,
		PrivateKey: p.k.Serialize(),
		// Parameters are omitted since they're specified in the algorithm identifier

		// Pubkey could be omitted, but we include it to match openssl behavior
		PublicKey: asn1.BitString{
			Bytes:     pubkeyBytes,
			BitLength: 8 * len(pubkeyBytes),
		},
	}

	ecPrivKeyDER, err := asn1.Marshal(ecPrivateKey)
	if err != nil {
		panic(err) // This should not happen with valid key data
	}

	// Create the PKCS#8 structure
	pkcs8 := struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			// Elliptic curve public key (OID: 1.2.840.10045.2.1)
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: must(asn1.Marshal(oidSecp256k1)),
			},
		},
		PrivateKey: ecPrivKeyDER,
	}

	der, err := asn1.Marshal(pkcs8)
	if err != nil {
		panic(err) // This should not happen with valid key data
	}

	return der
}

func (p *PrivateKey) ToPKCS8PEM() string {
	der := p.ToPKCS8DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: der,
	}))
}

// The default signing hash is SHA-256.
func (p *PrivateKey) SignToBytes(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	params := crypto.CollectSigningOptions(opts)

	hasher := params.HashOrDefault(crypto.SHA256).New()
	hasher.Write(message)
	hash := hasher.Sum(nil)

	sig := ecdsa.Sign(p.k, hash)
	r := sig.R()
	s := sig.S()

	res := make([]byte, SignatureBytesSize)
	r.PutBytesUnchecked(res[:SignatureBytesSize/2])
	s.PutBytesUnchecked(res[SignatureBytesSize/2:])

	return res, nil
}

// The default signing hash is SHA-256.
func (p *PrivateKey) SignToASN1(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	params := crypto.CollectSigningOptions(opts)

	hasher := params.HashOrDefault(crypto.SHA256).New()
	hasher.Write(message)
	hash := hasher.Sum(nil)

	sig := ecdsa.Sign(p.k, hash)

	return sig.Serialize(), nil
}

func (p *PrivateKey) PublicKeyIsCompatible(remote crypto.PublicKey) bool {
	if _, ok := remote.(*PublicKey); ok {
		return true
	}
	return false
}

func (p *PrivateKey) KeyExchange(remote crypto.PublicKey) ([]byte, error) {
	if remote, ok := remote.(*PublicKey); ok {
		return secp256k1.GenerateSharedSecret(p.k, remote.k), nil
	}
	return nil, fmt.Errorf("incompatible public key")
}
