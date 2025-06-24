package didkey

import (
	"fmt"
	"strings"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/_helpers"
	"github.com/INFURA/go-did/crypto/ed25519"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/x25519"
	"github.com/INFURA/go-did/verifications/ed25519"
	"github.com/INFURA/go-did/verifications/multikey"
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
		return nil, fmt.Errorf("%w: must start with 'did:key'", did.ErrInvalidDid)
	}

	msi := identifier[len(keyPrefix):]

	code, bytes, err := helpers.PublicKeyMultibaseDecode(msi)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}

	decoder, ok := map[uint64]func(b []byte) (crypto.PublicKey, error){
		ed25519.MultibaseCode: func(b []byte) (crypto.PublicKey, error) { return ed25519.PublicKeyFromBytes(b) },
		p256.MultibaseCode:    func(b []byte) (crypto.PublicKey, error) { return p256.PublicKeyFromBytes(b) },
		x25519.MultibaseCode:  func(b []byte) (crypto.PublicKey, error) { return x25519.PublicKeyFromBytes(b) },
	}[code]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported did:key multicodec: 0x%x", did.ErrInvalidDid, code)
	}

	pub, err := decoder(bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	d, err := FromPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	return d, nil
}

func FromPublicKey(pub crypto.PublicKey) (did.DID, error) {
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		d := DidKey{msi: pub.ToPublicKeyMultibase()}
		d.signature = ed25519vm.NewVerificationKey2020(fmt.Sprintf("did:key:%s#%s", d.msi, d.msi), pub, d)
		xpub, err := x25519.PublicKeyFromEd25519(pub)
		if err != nil {
			return nil, err
		}
		xmsi := xpub.ToPublicKeyMultibase()
		d.keyAgreement = x25519vm.NewKeyAgreementKey2020(fmt.Sprintf("did:key:%s#%s", d.msi, xmsi), xpub, d)
		return d, nil
	case *p256.PublicKey:
		d := DidKey{msi: pub.ToPublicKeyMultibase()}
		mk := multikey.NewMultiKey(fmt.Sprintf("did:key:%s#%s", d.msi, d.msi), pub, d)
		d.signature = mk
		d.keyAgreement = mk
		return d, nil

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
