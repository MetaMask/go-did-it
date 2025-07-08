package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/INFURA/go-did/crypto"
)

var _ crypto.PrivateKeySigning = &PrivateKey{}

type PrivateKey struct {
	k *rsa.PrivateKey
}

func PrivateKeyFromNEDPQ(n, e, d, p, q []byte) (*PrivateKey, error) {
	pub, err := PublicKeyFromNE(n, e)
	if err != nil {
		return nil, err
	}
	dBInt := new(big.Int).SetBytes(d)
	pBInt := new(big.Int).SetBytes(p)
	qBInt := new(big.Int).SetBytes(q)

	priv := &rsa.PrivateKey{
		PublicKey: *pub.k,
		D:         dBInt,
		Primes:    []*big.Int{pBInt, qBInt},
	}

	// // while go doesn't care, we ensure to have the JWK canonical order of primes,
	// // so that the JWK code becomes simpler
	// if subtle.ConstantTimeCompare(p, q) > 0 {
	// 	priv.Primes[0], priv.Primes[1] = priv.Primes[1], priv.Primes[0]
	// }

	err = priv.Validate()
	if err != nil {
		return nil, err
	}
	priv.Precompute()

	return &PrivateKey{k: priv}, nil
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (*PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	rsaPriv := priv.(*rsa.PrivateKey)
	return &PrivateKey{k: rsaPriv}, nil
}

// PrivateKeyFromPKCS8PEM decodes an PKCS#8 PEM (string) encoded private key.
func PrivateKeyFromPKCS8PEM(str string) (*PrivateKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPrivBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PrivateKeyFromPKCS8DER(block.Bytes)
}

func (p *PrivateKey) BitLen() int {
	return p.k.N.BitLen()
}

func (p *PrivateKey) DBytes() []byte {
	byteLength := (p.k.D.BitLen() + 7) / 8 // Round up to the nearest byte
	buf := make([]byte, byteLength)
	p.k.D.FillBytes(buf)
	return buf
}

func (p *PrivateKey) PBytes() []byte {
	byteLength := (p.k.Primes[0].BitLen() + 7) / 8 // Round up to the nearest byte
	buf := make([]byte, byteLength)
	p.k.Primes[0].FillBytes(buf)
	return buf
}

func (p *PrivateKey) QBytes() []byte {
	byteLength := (p.k.Primes[1].BitLen() + 7) / 8 // Round up to the nearest byte
	buf := make([]byte, byteLength)
	p.k.Primes[1].FillBytes(buf)
	return buf
}

func (p *PrivateKey) DpBytes() []byte {
	if p.k.Precomputed.Dp == nil {
		p.k.Precompute()
	}
	byteLength := (p.k.Precomputed.Dp.BitLen() + 7) / 8 // Round up to the nearest byte
	buf := make([]byte, byteLength)
	p.k.Precomputed.Dp.FillBytes(buf)
	return buf
}

func (p *PrivateKey) DqBytes() []byte {
	if p.k.Precomputed.Dq == nil {
		p.k.Precompute()
	}
	byteLength := (p.k.Precomputed.Dq.BitLen() + 7) / 8 // Round up to the nearest byte
	buf := make([]byte, byteLength)
	p.k.Precomputed.Dq.FillBytes(buf)
	return buf
}

func (p *PrivateKey) QiBytes() []byte {
	if p.k.Precomputed.Qinv == nil {
		p.k.Precompute()
	}
	byteLength := (p.k.Precomputed.Qinv.BitLen() + 7) / 8 // Round up to the nearest byte
	buf := make([]byte, byteLength)
	p.k.Precomputed.Qinv.FillBytes(buf)
	return buf
}

func (p *PrivateKey) Equal(other crypto.PrivateKey) bool {
	if other, ok := other.(*PrivateKey); ok {
		return p.k.Equal(other.k)
	}
	return false
}

func (p *PrivateKey) Public() crypto.PublicKey {
	rsaPub := p.k.Public().(*rsa.PublicKey)
	return &PublicKey{k: rsaPub}
}

func (p *PrivateKey) ToPKCS8DER() []byte {
	res, _ := x509.MarshalPKCS8PrivateKey(p.k)
	return res
}

func (p *PrivateKey) ToPKCS8PEM() string {
	der := p.ToPKCS8DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: der,
	}))
}

func (p *PrivateKey) SignToBytes(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PrivateKey) SignToASN1(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// func (p *PrivateKey) PublicKeyIsCompatible(remote crypto.PublicKey) bool {
// 	if _, ok := remote.(*PublicKey); ok {
// 		return true
// 	}
// 	return false
// }
//
// func (p *PrivateKey) KeyExchange(remote crypto.PublicKey) ([]byte, error) {
// 	if remote, ok := remote.(*PublicKey); ok {
// 		// First, we need to convert the ECDSA (signing only) to the equivalent ECDH keys
// 		ecdhPriv, err := p.k.ECDH()
// 		if err != nil {
// 			return nil, err
// 		}
// 		ecdhPub, err := remote.k.ECDH()
// 		if err != nil {
// 			return nil, err
// 		}
//
// 		return ecdhPriv.ECDH(ecdhPub)
// 	}
// 	return nil, fmt.Errorf("incompatible public key")
// }
