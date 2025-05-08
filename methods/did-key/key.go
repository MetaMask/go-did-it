package didkey

import (
	"crypto"
	"fmt"
	"strings"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/verifications/ed25519"
	"github.com/INFURA/go-did/verifications/x25519"
)

// Specification: https://w3c-ccg.github.io/did-method-key/

func init() {
	did.RegisterMethod("key", Decode)
}

var _ did.DID = &DidKey{}

type DidKey struct {
	msi          string // method-specific identifier, i.e. "12345" in "did:key:12345"
	signature    did.VerificationMethodSignature
	keyAgreement did.VerificationMethodKeyAgreement
}

func Decode(identifier string) (did.DID, error) {
	const keyPrefix = "did:key:"

	if !strings.HasPrefix(identifier, keyPrefix) {
		return nil, fmt.Errorf("must start with 'did:key'")
	}

	msi := identifier[len(keyPrefix):]

	baseCodec, bytes, err := mbase.Decode(msi)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	// the specification enforces that encoding
	if baseCodec != mbase.Base58BTC {
		return nil, fmt.Errorf("%w: not Base58BTC encoded", did.ErrInvalidDid)
	}
	code, read, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}

	d := DidKey{msi: msi}

	switch code {
	case ed25519.MultibaseCode:
		d.signature, err = ed25519.NewVerificationKey2020(fmt.Sprintf("did:key:%s#%s", msi, msi), bytes[read:], d)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}
		xpub, err := x25519.PublicKeyFromEd25519(bytes[read:])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}
		xmsi := x25519.PublicKeyToMultibase(xpub)
		d.keyAgreement, err = x25519.NewKeyAgreementKey2020(fmt.Sprintf("did:key:%s#%s", msi, xmsi), xpub, d)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}

	// case P256: // TODO
	// case Secp256k1: // TODO
	// case RSA: // TODO
	default:
		return nil, fmt.Errorf("%w: unsupported did:key multicodec: 0x%x", did.ErrInvalidDid, code)
	}

	return d, nil
}

func FromPublicKey(pub PublicKey) (did.DID, error) {
	var err error
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		d := DidKey{
			msi: ed25519.PublicKeyToMultibase(pub),
		}
		d.signature, err = ed25519.NewVerificationKey2020(fmt.Sprintf("did:key:%s#%s", d.msi, d.msi), pub, d)
		if err != nil {
			return nil, err
		}
		return d, nil

	default:
		return nil, fmt.Errorf("unsupported public key: %T", pub)
	}
}

func FromPrivateKey(priv PrivateKey) (did.DID, error) {
	return FromPublicKey(priv.Public().(PublicKey))
}

func (d DidKey) Method() string {
	return "key"
}

func (d DidKey) Document() (did.Document, error) {
	return document{
		id:           d,
		signature:    d.signature,
		keyAgreement: d.keyAgreement,
	}, nil
}

func (d DidKey) String() string {
	return fmt.Sprintf("did:key:%s", d.msi)
}

func (d DidKey) ResolutionIsExpensive() bool {
	return false
}

func (d DidKey) Equal(d2 did.DID) bool {
	if d2, ok := d2.(DidKey); ok {
		return d.msi == d2.msi
	}
	return false
}

// ---------------

// Below are the interfaces for crypto.PublicKey and crypto.PrivateKey in the go standard library.
// They are not actually defined there for compatibility reasons.
// They are useful for did:key, it's unclear if it's useful elsewhere.

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}
