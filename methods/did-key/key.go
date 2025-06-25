package didkey

import (
	"fmt"
	"strings"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto"
	allkeys "github.com/INFURA/go-did/crypto/_allkeys"
	"github.com/INFURA/go-did/crypto/ed25519"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/p384"
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

	pub, err := allkeys.PublicKeyFromPublicKeyMultibase(msi)
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
	case *p256.PublicKey, *p384.PublicKey:
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
