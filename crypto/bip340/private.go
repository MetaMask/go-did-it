package bip340

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/MetaMask/go-did-it/crypto"
)

var _ crypto.PrivateKeySigningBytes = &PrivateKey{}
var _ crypto.PrivateKeyToBytes = &PrivateKey{}

type PrivateKey struct {
	k *secp256k1.PrivateKey
}

// PrivateKeyFromBytes parses a 32-byte private key and normalizes it so the
// corresponding public key has an even Y coordinate.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyBytesSize {
		return nil, fmt.Errorf("bip340: invalid private key size: expected %d bytes, got %d", PrivateKeyBytesSize, len(b))
	}
	priv := secp256k1.PrivKeyFromBytes(b)
	if priv.PubKey().Y().Bit(0) != 0 {
		priv.Key.Negate()
	}
	return &PrivateKey{k: priv}, nil
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

// SignToBytes signs the message using BIP-340 Schnorr and returns a 64-byte signature.
// Signing options are not supported as BIP-340 uses a fixed internal hash function.
func (p *PrivateKey) SignToBytes(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	if len(opts) != 0 {
		return nil, fmt.Errorf("bip340: SignToBytes does not support any options")
	}
	var auxRand [32]byte
	if _, err := rand.Read(auxRand[:]); err != nil {
		return nil, fmt.Errorf("bip340: failed to generate auxiliary randomness: %w", err)
	}

	return bip340Sign(&p.k.Key, p.k.PubKey(), message, auxRand)
}

// Unwrap returns the underlying secp256k1 private key.
func (p *PrivateKey) Unwrap() *secp256k1.PrivateKey {
	return p.k
}

// bip340Sign implements BIP-340 signing.
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
// Reference: https://github.com/btcsuite/btcd/blob/3a0df88/btcec/schnorr/signature.go#L393
//
// Preconditions: pubKey has even Y (enforced at key import/generation in this package),
// meaning d is already the normalized secret scalar — step 5 (negate if odd Y) is a no-op.
func bip340Sign(d *secp256k1.ModNScalar, pubKey *secp256k1.PublicKey, msg []byte, auxRand [32]byte) ([]byte, error) {
	// Step 1: let d' = int(d)
	// Step 2-3: validity checks (d != 0, d < n) guaranteed by secp256k1.PrivKeyFromBytes.
	// Step 4: let P = d'*G  — pubKey is already computed and stored.
	// Step 5: negate d if has_odd_y(P)  — no-op: caller guarantees even Y.
	var pubKeyBytes [32]byte
	pubKey.X().FillBytes(pubKeyBytes[:])

	// Serialize d to bytes; zero after use.
	var privBytes [32]byte
	d.PutBytes(&privBytes)
	defer func() {
		for i := range privBytes {
			privBytes[i] = 0
		}
	}()

	// Step 6: let t = bytes(d) XOR tagged_hash("BIP0340/aux", a)
	auxHash := taggedHash("BIP0340/aux", auxRand[:])
	var t [32]byte
	for i := range t {
		t[i] = privBytes[i] ^ auxHash[i]
	}
	defer func() {
		for i := range t {
			t[i] = 0
		}
	}()

	// Step 7: let rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m)
	// Step 8: let k' = int(rand) mod n
	nonceHash := taggedHash("BIP0340/nonce", t[:], pubKeyBytes[:], msg)
	defer func() {
		for i := range nonceHash {
			nonceHash[i] = 0
		}
	}()
	var k secp256k1.ModNScalar
	var nonceArr [32]byte
	copy(nonceArr[:], nonceHash)
	k.SetBytes(&nonceArr)

	// Step 9: fail if k' = 0
	if k.IsZero() {
		return nil, fmt.Errorf("bip340: generated nonce is zero")
	}

	// Step 10: let R = k'*G
	var R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k, &R)
	R.ToAffine()

	// Step 11: let k = k' if has_even_y(R), otherwise k = n - k'
	if R.Y.IsOdd() {
		k.Negate()
	}

	// Step 12: let e = int(tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m)) mod n
	var rBytes [32]byte
	R.X.PutBytes(&rBytes)
	commitment := taggedHash("BIP0340/challenge", rBytes[:], pubKeyBytes[:], msg)
	var e secp256k1.ModNScalar
	var commitmentArr [32]byte
	copy(commitmentArr[:], commitment)
	e.SetBytes(&commitmentArr)

	// Step 13: let sig = bytes(R.x) || bytes((k + e*d) mod n)
	s := new(secp256k1.ModNScalar).Mul2(&e, d).Add(&k)
	k.Zero()
	var sig [SignatureBytesSize]byte
	R.X.PutBytes((*[32]byte)(sig[:32]))
	s.PutBytes((*[32]byte)(sig[32:]))

	// Step 14: if Verify(bytes(P), m, sig) fails, abort.
	// Required by the spec as a fault-attack guard.
	var rField secp256k1.FieldVal
	rField.SetByteSlice(sig[:32])
	rField.Normalize()
	var sScalar secp256k1.ModNScalar
	sScalar.SetByteSlice(sig[32:])
	if !bip340Verify(&rField, &sScalar, pubKey, msg) {
		return nil, fmt.Errorf("bip340: produced signature failed verification")
	}

	return sig[:], nil
}

// taggedHash computes the BIP-340 tagged hash:
// SHA256(SHA256(tag) || SHA256(tag) || data...)
func taggedHash(tag string, data ...[]byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}
