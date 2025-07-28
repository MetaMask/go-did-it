package didplc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/MetaMask/go-did-it"
	allkeys "github.com/MetaMask/go-did-it/crypto/_allkeys"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/p384"
	"github.com/MetaMask/go-did-it/crypto/p521"
	"github.com/MetaMask/go-did-it/crypto/rsa"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
	ed25519vm "github.com/MetaMask/go-did-it/verifiers/_methods/ed25519"
	"github.com/MetaMask/go-did-it/verifiers/_methods/jsonwebkey"
	"github.com/MetaMask/go-did-it/verifiers/_methods/multikey"
	p256vm "github.com/MetaMask/go-did-it/verifiers/_methods/p256"
	secp256k1vm "github.com/MetaMask/go-did-it/verifiers/_methods/secp256k1"
)

// Specification: https://web.plc.directory/spec/v0.1/did-plc

const DefaultRegistry = "https://plc.directory"

func init() {
	did.RegisterMethod("plc", Decode)
}

var _ did.DID = DidPlc{}

type DidPlc struct {
	msi string // method-specific identifier, i.e. "12345" in "did:plc:12345"
}

func Decode(identifier string) (did.DID, error) {
	const plcPrefix = "did:plc:"

	if !strings.HasPrefix(identifier, plcPrefix) {
		return nil, fmt.Errorf("%w: must start with 'did:plc'", did.ErrInvalidDid)
	}

	msi := identifier[len(plcPrefix):]

	if len(msi) != 24 {
		return nil, fmt.Errorf("%w: incorrect did:plc identifier length", did.ErrInvalidDid)
	}

	for _, char := range msi {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= '2' && char <= '7':
		default:
			return nil, fmt.Errorf("%w: did:plc identifier contains invalid character", did.ErrInvalidDid)
		}
	}

	return DidPlc{msi: msi}, nil
}

func (d DidPlc) Method() string {
	return "plc"
}

func (d DidPlc) Document(opts ...did.ResolutionOption) (did.Document, error) {
	params := did.CollectResolutionOpts(opts)
	identifier := d.String()

	u, err := url.JoinPath(DefaultRegistry, identifier, "data")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(params.Context(), "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-did-it")

	res, err := params.HttpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrResolutionFailure, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", did.ErrResolutionFailure, res.StatusCode)
	}

	var aux struct {
		Did                 string            `json:"did"`
		VerificationMethods map[string]string `json:"verificationMethods"`
		// RotationKeys        []string          `json:"rotationKeys"`
		AlsoKnownAs []string `json:"alsoKnownAs"`
		Services    map[string]struct {
			Type     string `json:"type"`
			Endpoint string `json:"endpoint"`
		} `json:"services"`
	}

	// limit at 1MB to avoid abuse
	limiter := io.LimitReader(res.Body, 1<<20)
	err = json.NewDecoder(limiter).Decode(&aux)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrResolutionFailure, err)
	}

	if aux.Did != identifier {
		return nil, fmt.Errorf("%w: did:plc identifier mismatch", did.ErrResolutionFailure)
	}

	doc := &document{
		id:          aux.Did,
		alsoKnownAs: make([]*url.URL, len(aux.AlsoKnownAs)),
		signatures:  make([]did.VerificationMethodSignature, 0, len(aux.VerificationMethods)),
		services:    make(did.Services, 0, len(aux.Services)),
	}

	for i, aka := range aux.AlsoKnownAs {
		doc.alsoKnownAs[i], err = url.Parse(aka)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrResolutionFailure, err)
		}
	}

	for vmName, data := range aux.VerificationMethods {
		// decode the did:key. It's a similar handling as in the did:key implementation, but:
		// - the VM identifier is different
		// - did:plc doesn't seem to care about key agreement VM
		const keyPrefix = "did:key:"

		if !strings.HasPrefix(data, keyPrefix) {
			return nil, fmt.Errorf("%w: must start with 'did:key'", did.ErrInvalidDid)
		}
		msi := data[len(keyPrefix):]

		pub, err := allkeys.PublicKeyFromPublicKeyMultibase(msi)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}

		vmId := fmt.Sprintf("%s#%s", doc.id, vmName)

		switch pub := pub.(type) {
		case ed25519.PublicKey:
			switch {
			case params.HasVerificationMethodHint(jsonwebkey.Type):
				doc.signatures = append(doc.signatures, jsonwebkey.NewJsonWebKey2020(vmId, pub, d))
			case params.HasVerificationMethodHint(multikey.Type):
				doc.signatures = append(doc.signatures, multikey.NewMultiKey(vmId, pub, d))
			default:
				if params.HasVerificationMethodHint(ed25519vm.Type2018) {
					doc.signatures = append(doc.signatures, ed25519vm.NewVerificationKey2018(vmId, pub, d))
				} else {
					doc.signatures = append(doc.signatures, ed25519vm.NewVerificationKey2020(vmId, pub, d))
				}
			}
		case *p256.PublicKey:
			switch {
			case params.HasVerificationMethodHint(jsonwebkey.Type):
				doc.signatures = append(doc.signatures, jsonwebkey.NewJsonWebKey2020(vmId, pub, d))
			case params.HasVerificationMethodHint(p256vm.Type2021):
				doc.signatures = append(doc.signatures, p256vm.NewKey2021(vmId, pub, d))
			default:
				doc.signatures = append(doc.signatures, multikey.NewMultiKey(vmId, pub, d))
			}

		case *secp256k1.PublicKey:
			switch {
			case params.HasVerificationMethodHint(jsonwebkey.Type):
				doc.signatures = append(doc.signatures, jsonwebkey.NewJsonWebKey2020(vmId, pub, d))
			case params.HasVerificationMethodHint(secp256k1vm.Type2019):
				doc.signatures = append(doc.signatures, secp256k1vm.NewVerificationKey2019(vmId, pub, d))
			default:
				doc.signatures = append(doc.signatures, multikey.NewMultiKey(vmId, pub, d))
			}

		case *p384.PublicKey, *p521.PublicKey, *rsa.PublicKey:
			switch {
			case params.HasVerificationMethodHint(jsonwebkey.Type):
				doc.signatures = append(doc.signatures, jsonwebkey.NewJsonWebKey2020(vmId, pub, d))
			default:
				doc.signatures = append(doc.signatures, multikey.NewMultiKey(vmId, pub, d))
			}

		default:
			return nil, fmt.Errorf("unsupported public key: %T", pub)
		}
	}

	for id, service := range aux.Services {
		doc.services = append(doc.services, did.Service{
			Id:        "#" + id,
			Types:     []string{service.Type},
			Endpoints: []any{did.StrEndpoint(service.Endpoint)},
		})
	}

	return doc, nil
}

func (d DidPlc) String() string {
	return fmt.Sprintf("did:plc:%s", d.msi)
}

func (d DidPlc) ResolutionIsExpensive() bool {
	// requires an external HTTP request
	return true
}

func (d DidPlc) Equal(d2 did.DID) bool {
	if d2, ok := d2.(DidPlc); ok {
		return d.msi == d2.msi
	}
	if d2, ok := d2.(*DidPlc); ok {
		return d.msi == d2.msi
	}
	return false
}
