package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

type PublicKey = ed25519.PublicKey
type PrivateKey = ed25519.PrivateKey

func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// PublicKeyToMultibase encodes the public key in a suitable way for publicKeyMultibase
func PublicKeyToMultibase(pub PublicKey) string {
	// can only fail with an invalid encoding, but it's hardcoded
	bytes, _ := mbase.Encode(mbase.Base58BTC, append(varint.ToUvarint(MultibaseCode), pub...))
	return bytes
}

// MultibaseToPublicKey decodes the public key from its publicKeyMultibase form
func MultibaseToPublicKey(multibase string) (PublicKey, error) {
	baseCodec, bytes, err := mbase.Decode(multibase)
	if err != nil {
		return nil, err
	}
	// the specification enforces that encoding
	if baseCodec != mbase.Base58BTC {
		return nil, fmt.Errorf("not Base58BTC encoded")
	}
	code, read, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, err
	}
	if code != MultibaseCode {
		return nil, fmt.Errorf("invalid code")
	}
	if read != 2 {
		return nil, fmt.Errorf("unexpected multibase")
	}
	if len(bytes)-read != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}
	return bytes[read:], nil
}
