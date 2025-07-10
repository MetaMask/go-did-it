package didkey

import (
	"fmt"
	"strings"

	"github.com/ucan-wg/go-did-it"
	"github.com/ucan-wg/go-did-it/crypto"
	allkeys "github.com/ucan-wg/go-did-it/crypto/_allkeys"
	"github.com/ucan-wg/go-did-it/crypto/ed25519"
	"github.com/ucan-wg/go-did-it/crypto/p256"
	"github.com/ucan-wg/go-did-it/crypto/p384"
	"github.com/ucan-wg/go-did-it/crypto/p521"
	"github.com/ucan-wg/go-did-it/crypto/rsa"
	"github.com/ucan-wg/go-did-it/crypto/secp256k1"
	"github.com/ucan-wg/go-did-it/crypto/x25519"
	"github.com/ucan-wg/go-did-it/verifiers/_methods/ed25519"
	"github.com/ucan-wg/go-did-it/verifiers/_methods/jsonwebkey"
	"github.com/ucan-wg/go-did-it/verifiers/_methods/multikey"
	"github.com/ucan-wg/go-did-it/verifiers/_methods/p256"
	"github.com/ucan-wg/go-did-it/verifiers/_methods/secp256k1"
	"github.com/ucan-wg/go-did-it/verifiers/_methods/x25519"
)

// Specification: https://w3c-ccg.github.io/did-method-key/

func init() {
	did.RegisterMethod("key", Decode)
}

var _ did.DID = DidKey{}

type DidKey struct {
	msi    string // method-specific identifier, i.e. "12345" in "did:key:12345"
	pubkey crypto.PublicKey
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
	return DidKey{msi: msi, pubkey: pub}, nil
}

func FromPublicKey(pub crypto.PublicKey) did.DID {
	return DidKey{msi: pub.ToPublicKeyMultibase(), pubkey: pub}
}

func FromPrivateKey(priv crypto.PrivateKey) did.DID {
	return FromPublicKey(priv.Public().(crypto.PublicKey))
}

func (d DidKey) Method() string {
	return "key"
}

func (d DidKey) Document(opts ...did.ResolutionOption) (did.Document, error) {
	params := did.CollectResolutionOpts(opts)

	doc := document{id: d}
	mainVmId := fmt.Sprintf("did:key:%s#%s", d.msi, d.msi)

	switch pub := d.pubkey.(type) {
	case ed25519.PublicKey:
		xpub, err := x25519.PublicKeyFromEd25519(pub)
		if err != nil {
			return nil, err
		}
		xmsi := xpub.ToPublicKeyMultibase()
		xVmId := fmt.Sprintf("did:key:%s#%s", d.msi, xmsi)

		switch {
		case params.HasVerificationMethodHint(jsonwebkey.Type):
			doc.signature = jsonwebkey.NewJsonWebKey2020(mainVmId, pub, d)
			doc.keyAgreement = jsonwebkey.NewJsonWebKey2020(xVmId, xpub, d)
		case params.HasVerificationMethodHint(multikey.Type):
			doc.signature = multikey.NewMultiKey(mainVmId, pub, d)
			doc.keyAgreement = multikey.NewMultiKey(xVmId, xpub, d)
		default:
			if params.HasVerificationMethodHint(ed25519vm.Type2018) {
				doc.signature = ed25519vm.NewVerificationKey2018(mainVmId, pub, d)
			}
			if params.HasVerificationMethodHint(x25519vm.Type2019) {
				doc.keyAgreement = x25519vm.NewKeyAgreementKey2019(xVmId, xpub, d)
			}
			if doc.signature == nil {
				doc.signature = ed25519vm.NewVerificationKey2020(mainVmId, pub, d)
			}
			if doc.keyAgreement == nil {
				doc.keyAgreement = x25519vm.NewKeyAgreementKey2020(xVmId, xpub, d)
			}
		}

	case *p256.PublicKey:
		switch {
		case params.HasVerificationMethodHint(jsonwebkey.Type):
			jwk := jsonwebkey.NewJsonWebKey2020(mainVmId, pub, d)
			doc.signature = jwk
			doc.keyAgreement = jwk
		case params.HasVerificationMethodHint(p256vm.Type2021):
			vm := p256vm.NewKey2021(mainVmId, pub, d)
			doc.signature = vm
			doc.keyAgreement = vm
		default:
			mk := multikey.NewMultiKey(mainVmId, pub, d)
			doc.signature = mk
			doc.keyAgreement = mk
		}

	case *secp256k1.PublicKey:
		switch {
		case params.HasVerificationMethodHint(jsonwebkey.Type):
			jwk := jsonwebkey.NewJsonWebKey2020(mainVmId, pub, d)
			doc.signature = jwk
			doc.keyAgreement = jwk
		case params.HasVerificationMethodHint(secp256k1vm.Type2019):
			vm := secp256k1vm.NewVerificationKey2019(mainVmId, pub, d)
			doc.signature = vm
			doc.keyAgreement = vm
		default:
			mk := multikey.NewMultiKey(mainVmId, pub, d)
			doc.signature = mk
			doc.keyAgreement = mk
		}

	case *p384.PublicKey, *p521.PublicKey, *rsa.PublicKey:
		switch {
		case params.HasVerificationMethodHint(jsonwebkey.Type):
			jwk := jsonwebkey.NewJsonWebKey2020(mainVmId, pub, d)
			doc.signature = jwk
			doc.keyAgreement = jwk
		default:
			mk := multikey.NewMultiKey(mainVmId, pub, d)
			doc.signature = mk
			doc.keyAgreement = mk
		}

	default:
		return nil, fmt.Errorf("unsupported public key: %T", pub)
	}

	return doc, nil
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
	if d2, ok := d2.(*DidKey); ok {
		return d.msi == d2.msi
	}
	return false
}
