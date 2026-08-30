package didplcctl

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MetaMask/go-did-it/crypto"
)

// Keys in did:plc, which are carried as did:key strings wherever they appear — rotation
// keys and verification methods alike. This file is the vocabulary: what a rotation key
// is, how one is written and read as a did:key, and whether a signer holds one. Applying
// a key policy to a whole operation's worth of them is the codec's job, in codec.go.

// Signer is a private key able to sign did:plc operations. It must be a secp256k1 or
// P-256 key, and must be one of the rotation keys of the state being signed.
//
// did:plc requires low-S signatures; this package always passes
// [crypto.WithEcdsaLowSSig] when signing.
type Signer = crypto.PrivateKeySigningBytes

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

// publicKeys projects the decoded keys of a rotation key list, in order, widened for [State].
func publicKeys(keys []rotationKey) []crypto.PublicKey {
	out := make([]crypto.PublicKey, len(keys))
	for i, k := range keys {
		out[i] = k.pub
	}
	return out
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
