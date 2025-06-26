package jwk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/ed25519"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/p384"
	"github.com/INFURA/go-did/crypto/p521"
	"github.com/INFURA/go-did/crypto/secp256k1"
	"github.com/INFURA/go-did/crypto/x25519"
)

type PrivateJwk struct {
	Privkey crypto.PrivateKey
}

func (pj PrivateJwk) UnmarshalJSON(bytes []byte) error {
	aux := make(map[string]string)
	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}

	switch aux["kty"] {
	case "EC": // Elliptic curve
		// we only use D, ignore X/Y which will be recomputed from D
		d, err := base64.RawURLEncoding.DecodeString(aux["d"])
		if err != nil {
			return fmt.Errorf("invalid d parameter with kty=EC: %w", err)
		}
		switch aux["crv"] {
		case "P-256":
			pj.Privkey, err = p256.PrivateKeyFromBytes(d)
			return err
		case "P-384":
			pj.Privkey, err = p384.PrivateKeyFromBytes(d)
			return err
		case "P-521":
			pj.Privkey, err = p521.PrivateKeyFromBytes(d)
			return err
		case "secp256k1":
			pj.Privkey, err = secp256k1.PrivateKeyFromBytes(d)
			return err

		default:
			return fmt.Errorf("unsupported Curve %s", aux["crv"])
		}

	case "RSA":
		return fmt.Errorf("not implemented")

	case "OKP": // Octet key pair
		x, err := base64.RawURLEncoding.DecodeString(aux["x"])
		if err != nil {
			return fmt.Errorf("invalid x parameter with kty=OKP: %w", err)
		}
		switch aux["crv"] {
		case "Ed25519":
			pj.Privkey, err = ed25519.PrivateKeyFromBytes(x)
			return err
		case "X25519":
			pj.Privkey, err = x25519.PrivateKeyFromBytes(x)
			return err

		default:
			return fmt.Errorf("unsupported Curve %s", aux["crv"])
		}

	default:
		return fmt.Errorf("unsupported key type %s", aux["kty"])
	}
}
