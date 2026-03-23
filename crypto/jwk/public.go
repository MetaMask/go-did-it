package jwk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/p384"
	"github.com/MetaMask/go-did-it/crypto/p521"
	"github.com/MetaMask/go-did-it/crypto/rsa"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/MetaMask/go-did-it/crypto/x25519"
)

// Specification:
// - https://www.rfc-editor.org/rfc/rfc7517#section-4 (JWK)
// - https://www.iana.org/assignments/jose/jose.xhtml#web-key-types (key parameters)

// PublicJwk is a JWK holding a public key
type PublicJwk struct {
	Pubkey crypto.PublicKey
	Kid    string // optional
	Use    string // optional; "sig" or "enc" per RFC 7517 §4.2
}

func (pj PublicJwk) MarshalJSON() ([]byte, error) {
	switch pubkey := pj.Pubkey.(type) {
	case ed25519.PublicKey:
		return json.Marshal(struct {
			Kid string `json:"kid,omitempty"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		}{
			Kid: pj.Kid,
			Use: pj.Use,
			Alg: validAlgs[keyTypeEd25519][0],
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.ToBytes()),
		})
	case *p256.PublicKey:
		return json.Marshal(struct {
			Kid string `json:"kid,omitempty"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kid: pj.Kid,
			Use: pj.Use,
			Alg: validAlgs[keyTypeP256][0],
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *p384.PublicKey:
		return json.Marshal(struct {
			Kid string `json:"kid,omitempty"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kid: pj.Kid,
			Use: pj.Use,
			Alg: validAlgs[keyTypeP384][0],
			Kty: "EC",
			Crv: "P-384",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *p521.PublicKey:
		return json.Marshal(struct {
			Kid string `json:"kid,omitempty"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kid: pj.Kid,
			Use: pj.Use,
			Alg: validAlgs[keyTypeP521][0],
			Kty: "EC",
			Crv: "P-521",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *rsa.PublicKey:
		return json.Marshal(struct {
			Kid string `json:"kid,omitempty"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		}{
			Kid: pj.Kid,
			Use: pj.Use,
			Alg: validAlgs[rsaKeyType(int(pubkey.KeyLength())*8)][0],
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pubkey.NBytes()),
			E:   base64.RawURLEncoding.EncodeToString(pubkey.EBytes()),
		})
	case *secp256k1.PublicKey:
		return json.Marshal(struct {
			Kid string `json:"kid,omitempty"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Kid: pj.Kid,
			Use: pj.Use,
			Alg: validAlgs[keyTypeSecp256k1][0],
			Kty: "EC",
			Crv: "secp256k1",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
		})
	case *x25519.PublicKey:
		return json.Marshal(struct {
			Kid string `json:"kid,omitempty"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		}{
			Kid: pj.Kid,
			Use: pj.Use,
			Alg: validAlgs[keyTypeX25519][0],
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

	pj.Kid = aux["kid"]
	pj.Use = aux["use"]

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
			if pj.Pubkey, err = p256.PublicKeyFromXY(x, y); err != nil {
				return err
			}
			return checkAlg(aux["alg"], keyTypeP256)
		case "P-384":
			if pj.Pubkey, err = p384.PublicKeyFromXY(x, y); err != nil {
				return err
			}
			return checkAlg(aux["alg"], keyTypeP384)
		case "P-521":
			if pj.Pubkey, err = p521.PublicKeyFromXY(x, y); err != nil {
				return err
			}
			return checkAlg(aux["alg"], keyTypeP521)
		case "secp256k1":
			if pj.Pubkey, err = secp256k1.PublicKeyFromXY(x, y); err != nil {
				return err
			}
			return checkAlg(aux["alg"], keyTypeSecp256k1)

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
		if pj.Pubkey, err = rsa.PublicKeyFromNE(n, e); err != nil {
			return err
		}
		return checkAlg(aux["alg"], rsaKeyType(int(pj.Pubkey.(*rsa.PublicKey).KeyLength())*8))

	case "OKP": // Octet key pair
		x, err := base64.RawURLEncoding.DecodeString(aux["x"])
		if err != nil {
			return fmt.Errorf("invalid x parameter with kty=OKP: %w", err)
		}
		switch aux["crv"] {
		case "Ed25519":
			if pj.Pubkey, err = ed25519.PublicKeyFromBytes(x); err != nil {
				return err
			}
			return checkAlg(aux["alg"], keyTypeEd25519)
		case "X25519":
			if pj.Pubkey, err = x25519.PublicKeyFromBytes(x); err != nil {
				return err
			}
			return checkAlg(aux["alg"], keyTypeX25519)

		default:
			return fmt.Errorf("unsupported Curve %s", aux["crv"])
		}

	default:
		return fmt.Errorf("unsupported key type %s", aux["kty"])
	}
}
