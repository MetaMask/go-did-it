package didkey

import (
	"fmt"
	"strings"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/ed25519"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/x25519"
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

	switch code {
	case ed25519.MultibaseCode:
		pub, err := ed25519.PublicKeyFromBytes(bytes[read:])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}
		return FromPublicKey(pub)
	case p256.MultibaseCode:
		pub, err := p256.PublicKeyFromBytes(bytes[read:])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}
		return FromPublicKey(pub)

		// case Secp256k1: // TODO
		// case RSA: // TODO
	}

	return nil, fmt.Errorf("%w: unsupported did:key multicodec: 0x%x", did.ErrInvalidDid, code)
}

func FromPublicKey(pub crypto.PublicKey) (did.DID, error) {
	var err error
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		d := DidKey{msi: pub.ToPublicKeyMultibase()}
		d.signature, err = ed25519vm.NewVerificationKey2020(fmt.Sprintf("did:key:%s#%s", d.msi, d.msi), pub, d)
		if err != nil {
			return nil, err
		}
		xpub, err := x25519.PublicKeyFromEd25519(pub)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}
		xmsi := xpub.ToPublicKeyMultibase()
		d.keyAgreement, err = x25519vm.NewKeyAgreementKey2020(fmt.Sprintf("did:key:%s#%s", d.msi, xmsi), xpub, d)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}
		return d, nil
	// case *p256.PublicKey:
	// 	d := DidKey{msi: pub.ToPublicKeyMultibase()}

	default:
		return nil, fmt.Errorf("unsupported public key: %T", pub)
	}
}

func FromPrivateKey(priv crypto.PrivateKey) (did.DID, error) {
	return FromPublicKey(priv.Public().(crypto.PublicKey))
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
