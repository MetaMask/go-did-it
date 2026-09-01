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
	// key later in this list. Between 1 and 10 keys, secp256k1 or P-256. A duplicate is
	// allowed but pointless, conferring the authority of its first position only.
	RotationKeys []crypto.PublicKey
	// VerificationMethods are the keys published in the DID document, keyed by the name
	// they appear under (without a leading '#'). At most 10, names at most 32 characters.
	VerificationMethods map[string]crypto.PublicKey
	// AlsoKnownAs are other identifiers for the subject, in descending order of preference.
	// For atproto this holds the "at://" handle. The specification calls them URIs, but the
	// registry does not require that and real DIDs do not respect it, so neither does this
	// package. At most 10, each at most 258 characters, no duplicates.
	AlsoKnownAs []string
	// Services are the subject's service endpoints, keyed by the name they appear under
	// (without a leading '#'). At most 10, names at most 32 characters.
	Services map[string]Service
}

// Service is a did:plc service endpoint.
type Service struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

func validateAlsoKnownAs(akas []string) error {
	if len(akas) > maxAlsoKnownAs {
		return fmt.Errorf("alsoKnownAs: at most %d entries allowed, got %d", maxAlsoKnownAs, len(akas))
	}
	seen := make(map[string]int, len(akas))
	for i, aka := range akas {
		// Deliberately not checked: that the entry is a URI, or has a scheme. The
		// specification describes alsoKnownAs as a list of URIs, but the registry validates
		// nothing about their syntax, and a third of the operations in live traffic carry an
		// entry that is not a URI at all — a bare base32 identifier alongside the at://
		// handle. Requiring a scheme would leave every one of those DIDs readable but
		// impossible to update.
		if _, err := url.Parse(aka); err != nil {
			return fmt.Errorf("alsoKnownAs %d: %q is malformed: %w", i, aka, err)
		}
		if len(aka) > maxAlsoKnownAsLength {
			return fmt.Errorf("alsoKnownAs %d: %d characters, over the %d limit", i, len(aka), maxAlsoKnownAsLength)
		}
		// The registry rejects duplicates, so writing one can only fail; unlike a
		// duplicate rotation key, which it allows.
		if j, dup := seen[aka]; dup {
			return fmt.Errorf("alsoKnownAs %d and %d are both %q: the registry rejects duplicates", j, i, aka)
		}
		seen[aka] = i
	}
	return nil
}

func validateServices(svcs map[string]Service) error {
	if len(svcs) > maxServices {
		return fmt.Errorf("services: at most %d entries allowed, got %d", maxServices, len(svcs))
	}
	for name, svc := range svcs {
		if err := validateName("service", name); err != nil {
			return err
		}
		if svc.Type == "" {
			return fmt.Errorf("service %q: empty type", name)
		}
		if len(svc.Type) > maxServiceTypeLength {
			return fmt.Errorf("service %q: type is %d characters, over the %d limit", name, len(svc.Type), maxServiceTypeLength)
		}
		u, err := url.Parse(svc.Endpoint)
		if err != nil {
			return fmt.Errorf("service %q: endpoint %q is not a valid URL: %w", name, svc.Endpoint, err)
		}
		if u.Scheme == "" {
			return fmt.Errorf("service %q: endpoint %q has no scheme", name, svc.Endpoint)
		}
		if len(svc.Endpoint) > maxServiceEndpointLength {
			return fmt.Errorf("service %q: endpoint is %d characters, over the %d limit",
				name, len(svc.Endpoint), maxServiceEndpointLength)
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
	if len(name) > maxNameLength {
		return fmt.Errorf("%s %q: name is %d characters, over the %d limit", kind, name, len(name), maxNameLength)
	}
	return nil
}
