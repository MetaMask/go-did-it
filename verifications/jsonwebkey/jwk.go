package jsonwebkey

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/ed25519"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/p384"
	"github.com/INFURA/go-did/crypto/x25519"
)

// Specification:
// - https://www.rfc-editor.org/rfc/rfc7517#section-4 (JWK)
// - https://www.iana.org/assignments/jose/jose.xhtml#web-key-types (key parameters)

type jwk struct {
	pubkey crypto.PublicKey
}

func (j jwk) MarshalJSON() ([]byte, error) {
	switch pubkey := j.pubkey.(type) {
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
			X:   base64.RawURLEncoding.EncodeToString(pubkey.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.Y.Bytes()),
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
			X:   base64.RawURLEncoding.EncodeToString(pubkey.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.Y.Bytes()),
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

func (j *jwk) UnmarshalJSON(bytes []byte) error {
	aux := make(map[string]string)
	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}

	bigIntBase64Url := func(s string) (*big.Int, error) {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(raw), nil
	}

	switch aux["kty"] {
	case "EC": // Elliptic curve
		x, err := bigIntBase64Url(aux["x"])
		if err != nil {
			return fmt.Errorf("invalid x parameter with kty=EC: %w", err)
		}
		y, err := bigIntBase64Url(aux["y"])
		if err != nil {
			return fmt.Errorf("invalid y parameter with kty=EC: %w", err)
		}
		switch aux["crv"] {
		case "P-256":
			j.pubkey, err = p256.PublicKeyFromXY(x, y)
			return err
		case "P-384":
			j.pubkey, err = p384.PublicKeyFromXY(x, y)
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
			j.pubkey, err = ed25519.PublicKeyFromBytes(x)
			return err
		case "X25519":
			j.pubkey, err = x25519.PublicKeyFromBytes(x)
			return err

		default:
			return fmt.Errorf("unsupported Curve %s", aux["crv"])
		}

	default:
		return fmt.Errorf("unsupported key type %s", aux["kty"])
	}
}
