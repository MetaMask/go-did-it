package jwk

import "fmt"

type keyType int

const (
	keyTypeEd25519 keyType = iota
	keyTypeX25519
	keyTypeP256
	keyTypeP384
	keyTypeP521
	keyTypeSecp256k1
	keyTypeRSA256 // RSA keys ≤ 2048 bits
	keyTypeRSA384 // RSA keys ≤ 3072 bits
	keyTypeRSA512 // RSA keys > 3072 bits
)

// validAlgs maps a key type to all algorithm values valid for it per RFC 7518 / IANA JOSE Algorithms.
// The first entry is the default used when marshalling.
var validAlgs = map[keyType][]string{
	keyTypeEd25519:   {"EdDSA"},
	keyTypeX25519:    {"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"},
	keyTypeP256:      {"ES256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"},
	keyTypeP384:      {"ES384", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"},
	keyTypeP521:      {"ES512", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"},
	keyTypeSecp256k1: {"ES256K"},
	keyTypeRSA256:    {"RS256", "PS256", "RSA-OAEP", "RSA-OAEP-256", "RSA1_5"},
	keyTypeRSA384:    {"RS384", "PS384", "RSA-OAEP", "RSA-OAEP-256", "RSA1_5"},
	keyTypeRSA512:    {"RS512", "PS512", "RSA-OAEP", "RSA-OAEP-256", "RSA1_5"},
}

func checkAlg(alg string, kt keyType) error {
	if alg == "" {
		return nil
	}
	valid := validAlgs[kt]
	for _, v := range valid {
		if v == alg {
			return nil
		}
	}
	return fmt.Errorf("alg %q is not valid for this key type; expected one of %v", alg, valid)
}

// rsaKeyType returns the keyType for an RSA key of the given bit length,
// mirroring the hash selection in crypto/rsa.defaultSigHash.
func rsaKeyType(keyBits int) keyType {
	switch {
	case keyBits <= 2048:
		return keyTypeRSA256
	case keyBits <= 3072:
		return keyTypeRSA384
	default:
		return keyTypeRSA512
	}
}
