package didplcctl

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/MetaMask/go-did-it/crypto"
)

// Signer is a private key able to sign did:plc operations. It must be a secp256k1 or
// P-256 key, and must be one of the rotation keys of the state being signed.
//
// did:plc requires low-S signatures; this package always passes
// [crypto.WithEcdsaLowSSig] when signing.
type Signer = crypto.PrivateKeySigningBytes

// Op is the document state of a did:plc DID: the content an operation establishes,
// rather than the operation itself. [Controller.Update] hands out the current state and
// takes back the desired one; the operation that gets from one to the other is built
// and signed by this package.
type Op struct {
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

// rotationKey is one entry of an operation's rotation key list, in both the forms the
// protocol needs at once. The index in the list is the key's authority: a lower index
// outranks a higher one.
//
// Every rotation key is decoded exactly once, here at the edge of the package, and an
// operation whose rotation keys cannot all be decoded is rejected outright. That is what
// leaves the rules in chain.go needing no key policy of their own: by the time they see
// an operation, its keys are keys.
type rotationKey struct {
	// didKey is the wire form, which is what goes into the signed bytes.
	didKey string
	// pub is the decoded key. It is the signing-bytes interface rather than
	// [crypto.PublicKey] because checking a signature is the only thing it is for.
	pub crypto.PublicKeySigningBytes
}

// didKeys projects the wire form of a rotation key list, in order.
func didKeys(keys []rotationKey) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.didKey
	}
	return out
}

// publicKeys projects the decoded keys of a rotation key list, in order, widened for [Op].
func publicKeys(keys []rotationKey) []crypto.PublicKey {
	out := make([]crypto.PublicKey, len(keys))
	for i, k := range keys {
		out[i] = k.pub
	}
	return out
}

// Converting a caller-supplied Op to its wire form, checking it against the limits in
// spec.go on the way. Each of these turns what would otherwise be an opaque HTTP 400 from
// the registry into a local error.

// rotationKeysToWire validates a caller's rotation key list and converts it.
func (r *Registry) rotationKeysToWire(keys []crypto.PublicKey) ([]rotationKey, error) {
	if len(keys) < minRotationKeys || len(keys) > maxRotationKeys {
		return nil, fmt.Errorf("rotation keys: need %d to %d keys, got %d", minRotationKeys, maxRotationKeys, len(keys))
	}
	out := make([]rotationKey, len(keys))
	seen := make(map[string]int, len(keys))
	for i, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("rotation key %d is nil", i)
		}
		if err := r.rotationPolicy.CheckKey(key); err != nil {
			return nil, fmt.Errorf("rotation key %d: %w", i, err)
		}
		verifier, ok := key.(crypto.PublicKeySigningBytes)
		if !ok {
			return nil, fmt.Errorf("rotation key %d: %T cannot verify raw signatures", i, key)
		}
		dk := didKeyString(key)
		if j, dup := seen[dk]; dup {
			return nil, fmt.Errorf("rotation keys %d and %d are the same key: the specification forbids duplicates", j, i)
		}
		seen[dk] = i
		out[i] = rotationKey{didKey: dk, pub: verifier}
	}
	return out, nil
}

// verificationMethodsToWire validates a caller's verification methods and converts them.
// The keys are checked against the policy on the way out as well as on the way in, so a
// key this package hands out is always one it would accept back.
func (r *Registry) verificationMethodsToWire(vms map[string]crypto.PublicKey) (map[string]string, error) {
	if len(vms) > maxVerificationMethods {
		return nil, fmt.Errorf("verificationMethods: at most %d entries allowed, got %d", maxVerificationMethods, len(vms))
	}
	out := make(map[string]string, len(vms))
	for name, key := range vms {
		if err := validateName("verification method", name); err != nil {
			return nil, err
		}
		if key == nil {
			return nil, fmt.Errorf("verification method %q is nil", name)
		}
		if err := r.vmPolicy.CheckKey(key); err != nil {
			return nil, fmt.Errorf("verification method %q: %w", name, err)
		}
		out[name] = didKeyString(key)
	}
	return out, nil
}

// Converting the wire form back. Rotation keys go through the rotation key policy and
// verification methods through the verification method policy.

// rotationKeyFromWire decodes one rotation key.
func (r *Registry) rotationKeyFromWire(didKey string) (rotationKey, error) {
	pub, err := didKeyToPublicKey(r.rotationPolicy, didKey)
	if err != nil {
		return rotationKey{}, err
	}
	verifier, ok := pub.(crypto.PublicKeySigningBytes)
	if !ok {
		return rotationKey{}, fmt.Errorf("%T cannot verify raw signatures", pub)
	}
	return rotationKey{didKey: didKey, pub: verifier}, nil
}

// rotationKeysFromWire decodes an operation's rotation key list.
func (r *Registry) rotationKeysFromWire(didKeys []string) ([]rotationKey, error) {
	out := make([]rotationKey, len(didKeys))
	for i, dk := range didKeys {
		k, err := r.rotationKeyFromWire(dk)
		if err != nil {
			return nil, fmt.Errorf("rotation key %d: %w", i, err)
		}
		out[i] = k
	}
	return out, nil
}

// verificationMethodsFromWire decodes an operation's verification methods.
func (r *Registry) verificationMethodsFromWire(vms map[string]string) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey, len(vms))
	for name, dk := range vms {
		pub, err := didKeyToPublicKey(r.vmPolicy, dk)
		if err != nil {
			return nil, fmt.Errorf("verification method %q: %w", name, err)
		}
		out[name] = pub
	}
	return out, nil
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

// checkSignerAuthorized reports whether signer holds one of the rotation keys allowed to
// sign the operation being built. The registry enforces this too, but failing here keeps
// a controller from signing a state it has no authority over: were the state to come
// from a hostile registry listing that registry's own rotation keys, signing it would
// hand over the DID.
func checkSignerAuthorized(signer Signer, authorized []rotationKey) error {
	if signer == nil {
		return errors.New("no signer provided")
	}
	pub := signer.Public()
	if pub == nil {
		return errors.New("signer has no public key")
	}
	got := didKeyString(pub)
	keys := didKeys(authorized)
	if slices.Contains(keys, got) {
		return nil
	}
	return fmt.Errorf("signer %s is not one of the rotation keys allowed to sign this operation (%s)",
		got, strings.Join(keys, ", "))
}

// did:key conversion, the form every key takes inside an operation.

func didKeyString(pub crypto.PublicKey) string {
	return didKeyPrefix + pub.ToPublicKeyMultibase()
}

func didKeyToPublicKey(policy *crypto.KeyPolicy, didKey string) (crypto.PublicKey, error) {
	if !strings.HasPrefix(didKey, didKeyPrefix) {
		return nil, fmt.Errorf("not a did:key: %q", didKey)
	}
	return policy.PublicKeyFromMultibase(didKey[len(didKeyPrefix):])
}
