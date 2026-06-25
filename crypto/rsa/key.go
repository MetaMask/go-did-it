package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/MetaMask/go-did-it/crypto"
)

const (
	MultibaseCode = uint64(0x1205)

	MinRsaKeyBits = 2048
	MaxRsaKeyBits = 8192
)

func GenerateKeyPair(bits int) (*PublicKey, *PrivateKey, error) {
	if bits < MinRsaKeyBits || bits > MaxRsaKeyBits {
		return nil, nil, fmt.Errorf("invalid key size: %d", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{k: &priv.PublicKey}, &PrivateKey{k: priv}, nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)

func defaultSigHash(keyLen int) crypto.Hash {
	switch {
	case keyLen <= 2048:
		return crypto.SHA256
	case keyLen <= 3072:
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// KeyType returns the crypto.KeyType describing RSA, to be added to a crypto.KeySet.
//
// For RSA the accepted modulus sizes are part of the policy. Pass the exact sizes (in bits) to allow,
// e.g. rsa.KeyType(2048, 4096); pass none to accept any size within [MinRsaKeyBits, MaxRsaKeyBits].
func KeyType(sizes ...int) crypto.KeyType {
	checkSize := func(bits int) error {
		if len(sizes) == 0 {
			if bits < MinRsaKeyBits || bits > MaxRsaKeyBits {
				return fmt.Errorf("rsa key size %d not allowed", bits)
			}
			return nil
		}
		for _, s := range sizes {
			if s == bits {
				return nil
			}
		}
		return fmt.Errorf("rsa key size %d not allowed", bits)
	}
	return crypto.KeyType{
		Name: rsaName(sizes),
		Code: MultibaseCode,
		// The did:key spec encodes the RSA publicKeyMultibase body as PKCS#1 (RSAPublicKey) DER.
		DecodePublic: func(body []byte) (crypto.PublicKey, error) {
			k, err := PublicKeyFromPKCS1DER(body)
			if err != nil {
				return nil, err
			}
			if err := checkSize(k.k.N.BitLen()); err != nil {
				return nil, err
			}
			return k, nil
		},
		Matches: func(key crypto.PublicKey) bool {
			rk, ok := key.(*PublicKey)
			return ok && checkSize(rk.k.N.BitLen()) == nil
		},
	}
}

func rsaName(sizes []int) string {
	if len(sizes) == 0 {
		return "RSA"
	}
	name := "RSA-"
	for i, s := range sizes {
		if i > 0 {
			name += "/"
		}
		name += fmt.Sprintf("%d", s)
	}
	return name
}
