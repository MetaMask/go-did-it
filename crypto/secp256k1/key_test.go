package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/_testsuite"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "secp256k1",
	GenerateKeyPair:                 GenerateKeyPair,
	PublicKeyFromBytes:              PublicKeyFromBytes,
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromBytes:             PrivateKeyFromBytes,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	DefaultHash:                     crypto.SHA256,
	OtherHashes:                     []crypto.Hash{crypto.KECCAK_256},
	PublicKeyBytesSize:              PublicKeyBytesSize,
	PrivateKeyBytesSize:             PrivateKeyBytesSize,
	SignatureBytesSize:              SignatureBytesSize,
}

func TestSuite(t *testing.T) {
	testsuite.TestSuite(t, harness)
}

func BenchmarkSuite(b *testing.B) {
	testsuite.BenchSuite(b, harness)
}

func TestPublicKeyX509(t *testing.T) {
	// openssl ecparam -genkey -name secp256k1 | openssl pkcs8 -topk8 -nocrypt -out secp256k1-key.pem
	// openssl pkey -in secp256k1-key.pem -pubout -out secp256k1-pubkey.pem
	pem := `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEFVP6HKjIReiiUgrC+t+FjG5u0PXIoBmN
V1MMmoOFfKlrD/HuWUjjlw0mDKZcG7AM7JKPTWMOCcvUR2B8BUO3VQ==
-----END PUBLIC KEY-----
`

	pub, err := PublicKeyFromX509PEM(pem)
	require.NoError(t, err)

	rt := pub.ToX509PEM()
	require.Equal(t, pem, rt)
}

func TestPrivateKeyPKCS8(t *testing.T) {
	// openssl ecparam -genkey -name secp256k1 | openssl pkcs8 -topk8 -nocrypt -out secp256k1-key.pem
	pem := `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgZW9JcJ1kN+DW2IFgqKJu
KS+39/xVa0n2J+lCr7hYGTihRANCAAQVU/ocqMhF6KJSCsL634WMbm7Q9cigGY1X
Uwyag4V8qWsP8e5ZSOOXDSYMplwbsAzsko9NYw4Jy9RHYHwFQ7dV
-----END PRIVATE KEY-----
`

	priv, err := PrivateKeyFromPKCS8PEM(pem)
	require.NoError(t, err)

	rt := priv.ToPKCS8PEM()
	require.Equal(t, pem, rt)
}

func FuzzPrivateKeyFromPKCS8PEM(f *testing.F) {
	f.Add(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgZW9JcJ1kN+DW2IFgqKJu
KS+39/xVa0n2J+lCr7hYGTihRANCAAQVU/ocqMhF6KJSCsL634WMbm7Q9cigGY1X
Uwyag4V8qWsP8e5ZSOOXDSYMplwbsAzsko9NYw4Jy9RHYHwFQ7dV
-----END PRIVATE KEY-----
`)

	f.Fuzz(func(t *testing.T, data string) {
		// looking for panics
		_, _ = PrivateKeyFromPKCS8PEM(data)
	})
}
