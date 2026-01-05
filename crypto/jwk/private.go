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

// PrivateJwk is a JWK holding a private key
type PrivateJwk struct {
	Privkey crypto.PrivateKey
}

func (pj PrivateJwk) MarshalJSON() ([]byte, error) {
	switch privkey := pj.Privkey.(type) {
	case ed25519.PrivateKey:
		pubkey := privkey.Public().(ed25519.PublicKey)
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			D   string `json:"d"`
		}{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.ToBytes()),
			D:   base64.RawURLEncoding.EncodeToString(privkey.Seed()),
		})
	case *p256.PrivateKey:
		pubkey := privkey.Public().(*p256.PublicKey)
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			D   string `json:"d"`
		}{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
			D:   base64.RawURLEncoding.EncodeToString(privkey.ToBytes()),
		})
	case *p384.PrivateKey:
		pubkey := privkey.Public().(*p384.PublicKey)
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			D   string `json:"d"`
		}{
			Kty: "EC",
			Crv: "P-384",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
			D:   base64.RawURLEncoding.EncodeToString(privkey.ToBytes()),
		})
	case *p521.PrivateKey:
		pubkey := privkey.Public().(*p521.PublicKey)
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			D   string `json:"d"`
		}{
			Kty: "EC",
			Crv: "P-521",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
			D:   base64.RawURLEncoding.EncodeToString(privkey.ToBytes()),
		})
	case *rsa.PrivateKey:
		pubkey := privkey.Public().(*rsa.PublicKey)
		return json.Marshal(struct {
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
			D   string `json:"d"`
			P   string `json:"p"`
			Q   string `json:"q"`
			Dp  string `json:"dp"`
			Dq  string `json:"dq"`
			Qi  string `json:"qi"`
		}{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pubkey.NBytes()),
			E:   base64.RawURLEncoding.EncodeToString(pubkey.EBytes()),
			D:   base64.RawURLEncoding.EncodeToString(privkey.DBytes()),
			P:   base64.RawURLEncoding.EncodeToString(privkey.PBytes()),
			Q:   base64.RawURLEncoding.EncodeToString(privkey.QBytes()),
			Dp:  base64.RawURLEncoding.EncodeToString(privkey.DpBytes()),
			Dq:  base64.RawURLEncoding.EncodeToString(privkey.DqBytes()),
			Qi:  base64.RawURLEncoding.EncodeToString(privkey.QiBytes()),
		})
	case *secp256k1.PrivateKey:
		pubkey := privkey.Public().(*secp256k1.PublicKey)
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			D   string `json:"d"`
		}{
			Kty: "EC",
			Crv: "secp256k1",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.XBytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubkey.YBytes()),
			D:   base64.RawURLEncoding.EncodeToString(privkey.ToBytes()),
		})
	case *x25519.PrivateKey:
		pubkey := privkey.Public().(*x25519.PublicKey)
		return json.Marshal(struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			D   string `json:"d"`
		}{
			Kty: "OKP",
			Crv: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(pubkey.ToBytes()),
			D:   base64.RawURLEncoding.EncodeToString(privkey.ToBytes()),
		})

	default:
		return nil, fmt.Errorf("unsupported key type %T", privkey)
	}
}

func (pj *PrivateJwk) UnmarshalJSON(bytes []byte) error {
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
		// we only use N,E,D,P,Q ignore Dp/Dq/Qi which will be recomputed from other parameters
		n, err := base64.RawURLEncoding.DecodeString(aux["n"])
		if err != nil {
			return fmt.Errorf("invalid n parameter with kty=RSA: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(aux["e"])
		if err != nil {
			return fmt.Errorf("invalid e parameter with kty=RSA: %w", err)
		}
		d, err := base64.RawURLEncoding.DecodeString(aux["d"])
		if err != nil {
			return fmt.Errorf("invalid d parameter with kty=RSA: %w", err)
		}
		p, err := base64.RawURLEncoding.DecodeString(aux["p"])
		if err != nil {
			return fmt.Errorf("invalid p parameter with kty=RSA: %w", err)
		}
		q, err := base64.RawURLEncoding.DecodeString(aux["q"])
		if err != nil {
			return fmt.Errorf("invalid q parameter with kty=RSA: %w", err)
		}
		pj.Privkey, err = rsa.PrivateKeyFromNEDPQ(n, e, d, p, q)
		return err

	case "OKP": // Octet key pair
		d, err := base64.RawURLEncoding.DecodeString(aux["d"])
		if err != nil {
			return fmt.Errorf("invalid x parameter with kty=OKP: %w", err)
		}
		switch aux["crv"] {
		case "Ed25519":
			pj.Privkey, err = ed25519.PrivateKeyFromSeed(d)
			return err
		case "X25519":
			pj.Privkey, err = x25519.PrivateKeyFromBytes(d)
			return err

		default:
			return fmt.Errorf("unsupported Curve %s", aux["crv"])
		}

	default:
		return fmt.Errorf("unsupported key type %s", aux["kty"])
	}
}
