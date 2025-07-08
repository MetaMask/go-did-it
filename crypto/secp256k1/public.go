package secp256k1

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/INFURA/go-did/crypto"
	helpers "github.com/INFURA/go-did/crypto/internal"
)

var _ crypto.PublicKeySigning = &PublicKey{}

type PublicKey struct {
	k *secp256k1.PublicKey
}

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{k: pub}, nil
}

// PublicKeyFromXY converts x and y coordinates into a PublicKey.
func PublicKeyFromXY(x, y []byte) (*PublicKey, error) {
	var xf, yf secp256k1.FieldVal
	if xf.SetByteSlice(x) {
		return nil, fmt.Errorf("invalid secp255k1 public key")
	}
	if yf.SetByteSlice(y) {
		return nil, fmt.Errorf("invalid secp255k1 public key")
	}
	return &PublicKey{k: secp256k1.NewPublicKey(&xf, &yf)}, nil
}

// PublicKeyFromPublicKeyMultibase decodes the public key from its Multibase form
func PublicKeyFromPublicKeyMultibase(multibase string) (*PublicKey, error) {
	code, bytes, err := helpers.PublicKeyMultibaseDecode(multibase)
	if err != nil {
		return nil, err
	}
	if code != MultibaseCode {
		return nil, fmt.Errorf("invalid code")
	}
	return PublicKeyFromBytes(bytes)
}

// PublicKeyFromX509DER decodes an X.509 DER (binary) encoded public key.
func PublicKeyFromX509DER(bytes []byte) (*PublicKey, error) {
	// Parse the X.509 SubjectPublicKeyInfo structure
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	if _, err := asn1.Unmarshal(bytes, &spki); err != nil {
		return nil, fmt.Errorf("failed to parse X.509 SubjectPublicKeyInfo: %w", err)
	}

	// Check if this is an Elliptic curve public key (OID: 1.2.840.10045.2.1)
	if !spki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, fmt.Errorf("not an Elliptic curve public key, got OID: %v", spki.Algorithm.Algorithm)
	}

	// Extract the curve OID from parameters
	var namedCurveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &namedCurveOID); err != nil {
		return nil, fmt.Errorf("failed to parse curve parameters: %w", err)
	}
	// Check if this is secp256k1 (OID: 1.3.132.0.10)
	if !namedCurveOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf("unsupported curve, expected secp256k1 (1.3.132.0.10), got: %v", namedCurveOID)
	}

	pubKey, err := secp256k1.ParsePubKey(spki.SubjectPublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secp256k1 public key: %w", err)
	}

	return &PublicKey{k: pubKey}, nil
}

// PublicKeyFromX509PEM decodes an X.509 PEM (string) encoded public key.
func PublicKeyFromX509PEM(str string) (*PublicKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPubBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PublicKeyFromX509DER(block.Bytes)
}

func (p *PublicKey) XBytes() []byte {
	// fixed size buffer that can get allocated on the caller's stack after inlining.
	var buf [coordinateSize]byte
	p.k.X().FillBytes(buf[:])
	return buf[:]
}

func (p *PublicKey) YBytes() []byte {
	// fixed size buffer that can get allocated on the caller's stack after inlining.
	var buf [coordinateSize]byte
	p.k.Y().FillBytes(buf[:])
	return buf[:]
}

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if other, ok := other.(*PublicKey); ok {
		return p.k.IsEqual(other.k)
	}
	return false
}

func (p *PublicKey) ToBytes() []byte {
	// 33-byte compressed format
	return p.k.SerializeCompressed()
}

func (p *PublicKey) ToPublicKeyMultibase() string {
	return helpers.PublicKeyMultibaseEncode(MultibaseCode, p.k.SerializeCompressed())
}

func (p *PublicKey) ToX509DER() []byte {
	pubKeyBytes := p.k.SerializeUncompressed()

	// Create the X.509 SubjectPublicKeyInfo structure
	spki := struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: must(asn1.Marshal(oidSecp256k1)),
			},
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}

	der, err := asn1.Marshal(spki)
	if err != nil {
		panic(err) // This should not happen with valid key data
	}

	return der
}

func (p *PublicKey) ToX509PEM() string {
	der := p.ToX509DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: der,
	}))
}

/*
	Note: signatures for the crypto.PrivateKeySigning interface assumes SHA256,
	which should be correct almost always. If there is a need to use a different
	hash function, we can add separate functions that have that flexibility.
*/

func (p *PublicKey) VerifyBytes(message, signature []byte, opts ...crypto.SigningOption) bool {
	// if len(signature) != SignatureBytesSize {
	// 	return false
	// }
	//
	// // Hash the message with SHA-256
	// hash := sha256.Sum256(message)
	//
	// r := new(big.Int).SetBytes(signature[:SignatureBytesSize/2])
	// s := new(big.Int).SetBytes(signature[SignatureBytesSize/2:])
	//
	// return ecdsa.Verify(p.k, hash[:], r, s)
	panic("not implemented")
}

func (p *PublicKey) VerifyASN1(message, signature []byte, opts ...crypto.SigningOption) bool {
	// // Hash the message with SHA-256
	// hash := sha256.Sum256(message)
	//
	// return ecdsa.VerifyASN1(p.k, hash[:], signature)
	panic("not implemented")
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
