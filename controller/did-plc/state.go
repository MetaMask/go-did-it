package didplcctl

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/MetaMask/go-did-it/crypto"
)

// The document state a did:plc operation establishes, as callers hand it over, and the
// limits the specification puts on it. Checking those here turns what would otherwise be
// an opaque HTTP 400 from the registry into a local error.
//
// A State is not an operation and holds nothing about one: no prev, no signature, no
// identity. It is the payload; operation.go is the envelope.

// State is the document state of a did:plc DID: what an operation establishes.
// [Controller.Update] hands out the current state and takes back the desired one; the
// operation that gets from one to the other is built and signed by this package.
type State struct {
	// RotationKeys are the keys allowed to sign the next operation, in descending order
	// of authority: during the recovery window a key may nullify operations signed by a
	// key later in this list. Between 1 and 5 keys, no duplicates, secp256k1 or P-256.
	RotationKeys []crypto.PublicKey
	// VerificationMethods are the keys published in the DID document, keyed by the name
	// they appear under (without a leading '#'). At most 10.
	VerificationMethods map[string]crypto.PublicKey
	// AlsoKnownAs are other identifiers for the subject, as URIs, in descending order of
	// preference. For atproto this holds the "at://" handle.
	AlsoKnownAs []string
	// Services are the subject's service endpoints, keyed by the name they appear under
	// (without a leading '#').
	Services map[string]Service
}

// Service is a did:plc service endpoint.
type Service struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

func validateAlsoKnownAs(akas []string) error {
	for i, aka := range akas {
		u, err := url.Parse(aka)
		if err != nil {
			return fmt.Errorf("alsoKnownAs %d: %q is not a valid URI: %w", i, aka, err)
		}
		if u.Scheme == "" {
			return fmt.Errorf("alsoKnownAs %d: %q has no scheme, but the specification requires URIs (e.g. %q)", i, aka, "at://alice.example.com")
		}
	}
	return nil
}

func validateServices(svcs map[string]Service) error {
	for name, svc := range svcs {
		if err := validateName("service", name); err != nil {
			return err
		}
		if svc.Type == "" {
			return fmt.Errorf("service %q: empty type", name)
		}
		u, err := url.Parse(svc.Endpoint)
		if err != nil {
			return fmt.Errorf("service %q: endpoint %q is not a valid URL: %w", name, svc.Endpoint, err)
		}
		if u.Scheme == "" {
			return fmt.Errorf("service %q: endpoint %q has no scheme", name, svc.Endpoint)
		}
	}
	return nil
}

// validateName checks a verification method or service map key. These are rendered into
// the DID document as "#<name>" fragments, so a name carrying its own '#' would produce
// a malformed identifier.
func validateName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%s: empty name", kind)
	}
	if strings.Contains(name, "#") {
		return fmt.Errorf("%s %q: name must not contain '#', it is added when rendering the document", kind, name)
	}
	return nil
}
