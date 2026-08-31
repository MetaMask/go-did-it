package didkey

import (
	"errors"
	"fmt"
	"strings"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/p384"
	"github.com/MetaMask/go-did-it/crypto/p521"
	"github.com/MetaMask/go-did-it/crypto/rsa"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/MetaMask/go-did-it/crypto/x25519"
	"github.com/MetaMask/go-did-it/verifiers/methods/ed25519"
	"github.com/MetaMask/go-did-it/verifiers/methods/jsonwebkey"
	"github.com/MetaMask/go-did-it/verifiers/methods/multikey"
	"github.com/MetaMask/go-did-it/verifiers/methods/p256"
	"github.com/MetaMask/go-did-it/verifiers/methods/secp256k1"
	"github.com/MetaMask/go-did-it/verifiers/methods/x25519"
)

// Specification: https://w3c-ccg.github.io/did-method-key/

func init() {
	did.RegisterMethod("key", Decode)
}

var _ did.DID = DidKey{}

type DidKey struct {
	msi string // method-specific identifier, i.e. "12345" in "did:key:12345"
}

func Decode(identifier string) (did.DID, error) {
	const keyPrefix = "did:key:"

	if !strings.HasPrefix(identifier, keyPrefix) {
		return nil, fmt.Errorf("%w: must start with 'did:key'", did.ErrInvalidDid)
	}

	msi := identifier[len(keyPrefix):]

	// Validate the identifier syntax (multibase + multicodec prefix). Whether the key algorithm
	// is accepted is a policy decision deferred to Document(), where the caller provides the KeyPolicy.
	enc, data, err := mbase.Decode(msi)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	if enc != mbase.Base58BTC {
		return nil, fmt.Errorf("%w: not Base58BTC encoded", did.ErrInvalidDid)
	}
	n, read, err := varint.FromUvarint(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	if read == len(data) {
		return nil, fmt.Errorf("%w: multicodec prefix %#x is not followed by any key material", did.ErrInvalidDid, n)
	}

	return DidKey{msi: msi}, nil
}

func FromPublicKey(pub crypto.PublicKey) did.DID {
	return DidKey{msi: pub.ToPublicKeyMultibase()}
}

func FromPrivateKey(priv crypto.PrivateKey) did.DID {
	return FromPublicKey(priv.Public())
}

func (d DidKey) Method() string {
	return "key"
}

func (d DidKey) Document(opts ...did.ResolutionOption) (did.Document, error) {
	params := did.CollectResolutionOpts(opts)

	pub, err := params.KeyPolicy().PublicKeyFromMultibase(d.msi)
	if err != nil {
		// A declined algorithm is a policy decision of the caller, not a malformed identifier:
		// ErrInvalidDid means "does not conform to valid syntax", which this DID does. Report
		// the policy rejection as-is, and keep ErrInvalidDid for actually malformed key material.
		if errors.Is(err, crypto.ErrKeyNotAccepted) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}

	doc := document{id: d.String()}
	mainVmId := fmt.Sprintf("did:key:%s#%s", d.msi, d.msi)

	switch pub := pub.(type) {
	case ed25519.PublicKey:
		xpub, err := x25519.PublicKeyFromEd25519(pub)
		if err != nil {
			return nil, err
		}
		xmsi := xpub.ToPublicKeyMultibase()
		xVmId := fmt.Sprintf("did:key:%s#%s", d.msi, xmsi)

		// The derived X25519 key is subject to the key policy as well:
		// when excluded, the document simply has no keyAgreement.
		xAllowed := params.KeyPolicy().Accepts(xpub)

		switch {
		case params.HasVerificationMethodHint(jsonwebkey.Type):
			doc.signature = jsonwebkey.NewJsonWebKey2020(mainVmId, pub, d)
			if xAllowed {
				doc.keyAgreement = jsonwebkey.NewJsonWebKey2020(xVmId, xpub, d)
			}
		case params.HasVerificationMethodHint(multikey.Type):
			doc.signature = multikey.NewMultiKey(mainVmId, pub, d)
			if xAllowed {
				doc.keyAgreement = multikey.NewMultiKey(xVmId, xpub, d)
			}
		default:
			if params.HasVerificationMethodHint(ed25519vm.Type2018) {
				doc.signature = ed25519vm.NewVerificationKey2018(mainVmId, pub, d)
			}
			if xAllowed && params.HasVerificationMethodHint(x25519vm.Type2019) {
				doc.keyAgreement = x25519vm.NewKeyAgreementKey2019(xVmId, xpub, d)
			}
			if doc.signature == nil {
				doc.signature = ed25519vm.NewVerificationKey2020(mainVmId, pub, d)
			}
			if xAllowed && doc.keyAgreement == nil {
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
		case params.HasVerificationMethodHint(secp256k1vm.TypeVerification2019):
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
