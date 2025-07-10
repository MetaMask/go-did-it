package p256

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-did-it/crypto"
	"github.com/ucan-wg/go-did-it/crypto/_testsuite"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "p256",
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
	OtherHashes:                     []crypto.Hash{crypto.SHA224, crypto.SHA384, crypto.SHA512},
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

func TestSignatureASN1(t *testing.T) {
	// openssl ecparam -genkey -name prime256v1 -noout -out private.pem
	// openssl ec -in private.pem -pubout -out public.pem
	// echo -n "message" | openssl dgst -sha256 -sign private.pem -out signature.der
	// echo -n "message" | openssl dgst -sha256 -verify public.pem -signature signature.der

	pubPem := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+UhEHZqcaKn+qhNtMmW843ZTRkX/
6GzxOWoRD2nv3EewARM90akj2UAKwQjJR9ibm78XtdlryvWG1v8TWb8INA==
-----END PUBLIC KEY-----
`
	pub, err := PublicKeyFromX509PEM(pubPem)
	require.NoError(t, err)

	b64sig := `MEQCIHPslthrLAYgwfqYaUmtGJqwmH7sRf5FEnnKgzcHIF8fAiB9+qovdvN6yJKkBwoQCw798uWr
0nOUE55ftB8EgX/Jbg==`
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	require.NoError(t, err)

	require.True(t, pub.VerifyASN1([]byte("message"), sig))
}
