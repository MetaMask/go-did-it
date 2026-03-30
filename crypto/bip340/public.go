package bip340

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/MetaMask/go-did-it/crypto"
	helpers "github.com/MetaMask/go-did-it/crypto/internal"
)

var _ crypto.PublicKeySigningBytes = &PublicKey{}
var _ crypto.PublicKeyToBytes = &PublicKey{}

type PublicKey struct {
	k *secp256k1.PublicKey
}

// PublicKeyFromBytes parses a 32-byte x-only BIP-340 public key.
// The Y coordinate is reconstructed as even (lift_x).
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyBytesSize {
		return nil, fmt.Errorf("bip340: invalid public key size: expected %d bytes, got %d", PublicKeyBytesSize, len(b))
	}
	compressed := make([]byte, 33)
	compressed[0] = 0x02
	copy(compressed[1:], b)
	pub, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("bip340: failed to parse public key: %w", err)
	}
	return &PublicKey{k: pub}, nil
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

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if other, ok := other.(*PublicKey); ok {
		return p.k.IsEqual(other.k)
	}
	return false
}

// ToBytes returns the 32-byte x-only BIP-340 serialization of the public key.
func (p *PublicKey) ToBytes() []byte {
	var buf [PublicKeyBytesSize]byte
	p.k.X().FillBytes(buf[:])
	return buf[:]
}

func (p *PublicKey) ToPublicKeyMultibase() string {
	return helpers.PublicKeyMultibaseEncode(MultibaseCode, p.ToBytes())
}

// VerifyBytes verifies a 64-byte BIP-340 Schnorr signature.
// Signing options are not supported as BIP-340 uses a fixed internal hash function.
func (p *PublicKey) VerifyBytes(message, signature []byte, opts ...crypto.SigningOption) bool {
	if len(opts) != 0 {
		return false // VerifyBytes does not support any options
	}
	if len(signature) != SignatureBytesSize {
		return false
	}

	// Parse r (field element) and s (scalar) from signature.
	var r secp256k1.FieldVal
	if r.SetByteSlice(signature[:32]) {
		return false // r >= field prime
	}
	r.Normalize()
	var s secp256k1.ModNScalar
	if s.SetByteSlice(signature[32:]) {
		return false // s >= curve order n
	}

	return bip340Verify(&r, &s, p.k, message)
}

// Unwrap returns the underlying secp256k1 public key.
func (p *PublicKey) Unwrap() *secp256k1.PublicKey {
	return p.k
}

// bip340Verify implements BIP-340 verification.
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
// Reference: https://github.com/btcsuite/btcd/blob/3a0df88/btcec/schnorr/signature.go#L114
//
// Inputs: 32-byte public key P (x-only), message m, 64-byte signature (r, s).
// Preconditions: r is normalized, r < p, s < n (enforced by caller).
func bip340Verify(r *secp256k1.FieldVal, s *secp256k1.ModNScalar, pubKey *secp256k1.PublicKey, msgHash []byte) bool {
	// Step 1: let P = lift_x(public key)
	// Already done: pubKey was parsed via PublicKeyFromBytes which uses lift_x (0x02 prefix).

	// Step 2: let r = int(sig[ 0:32]); fail if r >= p  — checked by caller.
	// Step 3: let s = int(sig[32:64]); fail if s >= n  — checked by caller.

	// Step 4: let e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || m)) mod n
	var rBytes, pubKeyBytes [32]byte
	r.PutBytes(&rBytes)
	pubKey.X().FillBytes(pubKeyBytes[:])
	commitment := taggedHash("BIP0340/challenge", rBytes[:], pubKeyBytes[:], msgHash)
	var e secp256k1.ModNScalar
	var commitmentArr [32]byte
	copy(commitmentArr[:], commitment)
	e.SetBytes(&commitmentArr)
	e.Negate() // negate so we can compute s*G + (-e)*P instead of s*G - e*P

	// Step 5: let R = s*G - e*P
	var P, R, sG, eP secp256k1.JacobianPoint
	pubKey.AsJacobian(&P)
	secp256k1.ScalarBaseMultNonConst(s, &sG)
	secp256k1.ScalarMultNonConst(&e, &P, &eP)
	secp256k1.AddNonConst(&sG, &eP, &R)

	// Step 6: fail if is_infinite(R)
	if R.Z.IsZero() {
		return false
	}

	R.ToAffine()

	// Step 7: fail if not has_even_y(R)
	if R.Y.IsOdd() {
		return false
	}

	// Step 8: fail if x(R) != r
	R.X.Normalize()
	return r.Equals(&R.X)
}
