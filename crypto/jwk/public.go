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
	"github.com/INFURA/go-did/crypto/rsa"
	"github.com/INFURA/go-did/crypto/secp256k1"
	"github.com/INFURA/go-did/crypto/x25519"
)

// Specification:
// - https://www.rfc-editor.org/rfc/rfc7517#section-4 (JWK)
// - https://www.iana.org/assignments/jose/jose.xhtml#web-key-types (key parameters)

type PublicJwk struct {
	Pubkey crypto.PublicKey
}

func (pj PublicJwk) MarshalJSON() ([]byte, error) {
	switch pubkey := pj.Pubkey.(type) {
	case ed25519.PublicKey:
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		}{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.ToBytes()),
		})
	case *p256.PublicKey:
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *p384.PublicKey:
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kty: "EC",
			Crv: "P-384",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *p521.PublicKey:
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kty: "EC",
			Crv: "P-521",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *rsa.PublicKey:
		return json.Marshal(struct {
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		}{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pubkey.NBytes()),
			E:   base64.RawURLEncoding.EncodeToString(pubkey.EBytes()),
		})
	case *secp256k1.PublicKey:
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kty: "EC",
			Crv: "secp256k1",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *x25519.PublicKey:
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		}{
			Kty: "OKP",
			Crv: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.ToBytes()),
		})

	default:
		return nil, fmt.Errorf("unsupported key type %T", pubkey)
	}
}

func (pj *PublicJwk) UnmarshalJSON(bytes []byte) error {
	aux := make(map[string]string)
	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}

	switch aux["kty"] {
	case "EC": // Elliptic curve
		x, err := base64.RawURLEncoding.DecodeString(aux["x"])
		if err != nil {
			return fmt.Errorf("invalid x parameter with kty=EC: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(aux["y"])
		if err != nil {
			return fmt.Errorf("invalid y parameter with kty=EC: %w", err)
		}
		switch aux["crv"] {
		case "P-256":
			pj.Pubkey, err = p256.PublicKeyFromXY(x, y)
			return err
		case "P-384":
			pj.Pubkey, err = p384.PublicKeyFromXY(x, y)
			return err
		case "P-521":
			pj.Pubkey, err = p521.PublicKeyFromXY(x, y)
			return err
		case "secp256k1":
			pj.Pubkey, err = secp256k1.PublicKeyFromXY(x, y)
			return err

		default:
			return fmt.Errorf("unsupported Curve %s", aux["crv"])
		}

	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(aux["n"])
		if err != nil {
			return fmt.Errorf("invalid n parameter with kty=RSA: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(aux["e"])
		if err != nil {
			return fmt.Errorf("invalid e parameter with kty=RSA: %w", err)
		}
		pj.Pubkey, err = rsa.PublicKeyFromNE(n, e)
		return err

	case "OKP": // Octet key pair
		x, err := base64.RawURLEncoding.DecodeString(aux["x"])
		if err != nil {
			return fmt.Errorf("invalid x parameter with kty=OKP: %w", err)
		}
		switch aux["crv"] {
		case "Ed25519":
			pj.Pubkey, err = ed25519.PublicKeyFromBytes(x)
			return err
		case "X25519":
			pj.Pubkey, err = x25519.PublicKeyFromBytes(x)
			return err

		default:
			return fmt.Errorf("unsupported Curve %s", aux["crv"])
		}

	default:
		return fmt.Errorf("unsupported key type %s", aux["kty"])
	}
}
