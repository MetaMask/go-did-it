package rsa

import (
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/_testsuite"
	helpers "github.com/MetaMask/go-did-it/crypto/internal"
)

var harness2048 = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "rsa-2048",
	GenerateKeyPair:                 func() (*PublicKey, *PrivateKey, error) { return GenerateKeyPair(2048) },
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	DefaultHash:                     crypto.SHA256,
	OtherHashes:                     []crypto.Hash{crypto.SHA384, crypto.SHA512},
	SupportsPreHashed:               false,
}

var harness3072 = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "rsa-3072",
	GenerateKeyPair:                 func() (*PublicKey, *PrivateKey, error) { return GenerateKeyPair(3072) },
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	DefaultHash:                     crypto.SHA384,
	OtherHashes:                     []crypto.Hash{crypto.SHA512},
	SupportsPreHashed:               false,
}

var harness4096 = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "rsa-4096",
	GenerateKeyPair:                 func() (*PublicKey, *PrivateKey, error) { return GenerateKeyPair(4096) },
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	DefaultHash:                     crypto.SHA512,
	OtherHashes:                     []crypto.Hash{},
	SupportsPreHashed:               false,
}

func TestSuite2048(t *testing.T) {
	testsuite.TestSuite(t, harness2048)
}

func TestSuite3072(t *testing.T) {
	testsuite.TestSuite(t, harness3072)
}

func TestSuite4096(t *testing.T) {
	testsuite.TestSuite(t, harness4096)
}

func BenchmarkSuite2048(b *testing.B) {
	testsuite.BenchSuite(b, harness2048)
}

func BenchmarkSuite3072(b *testing.B) {
	testsuite.BenchSuite(b, harness3072)
}

func BenchmarkSuite4096(b *testing.B) {
	testsuite.BenchSuite(b, harness4096)
}

func TestPublicKeyX509(t *testing.T) {
	// openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	// openssl pkey -in private_key.pem -pubout -out public_key.pem
	pem := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLFQUbVVo/rctJaCzR5z
g622eUNBwZmA1vnDEXnHWBl3y5RJF5zyTdlouujjmEuu6qsXk1NCNQ3dLH2iquI8
iFFAhS4kTX6JS+wR3vHLhga1oFkPceGFEUG/3vxn52ozFs8hikhq/P09HmLub7Vc
VklwrGvTbEa5Fn/2Kz6olw5ExYI14Unsl+A3iw8AXPL9/acD+ehoyx3/zKFrVTKx
e9jdoWX8L7IpqM2HOSu23/3E2IwH2GdY0C8575AiD/O555hie7JHkzF3I4E85gPd
ZgXYFShIfgOzDV0q4oP0pzqYkErhdjOpigCMjDuIC4OueZYqYJrP2rdpzuqoqk07
NwIDAQAB
-----END PUBLIC KEY-----
`

	pub, err := PublicKeyFromX509PEM(pem)
	require.NoError(t, err)

	rt := pub.ToX509PEM()
	require.Equal(t, pem, rt)
}

func TestPrivateKeyPKCS8(t *testing.T) {
	// openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	pem := `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDIsVBRtVWj+ty0
loLNHnODrbZ5Q0HBmYDW+cMRecdYGXfLlEkXnPJN2Wi66OOYS67qqxeTU0I1Dd0s
faKq4jyIUUCFLiRNfolL7BHe8cuGBrWgWQ9x4YURQb/e/GfnajMWzyGKSGr8/T0e
Yu5vtVxWSXCsa9NsRrkWf/YrPqiXDkTFgjXhSeyX4DeLDwBc8v39pwP56GjLHf/M
oWtVMrF72N2hZfwvsimozYc5K7bf/cTYjAfYZ1jQLznvkCIP87nnmGJ7skeTMXcj
gTzmA91mBdgVKEh+A7MNXSrig/SnOpiQSuF2M6mKAIyMO4gLg655lipgms/at2nO
6qiqTTs3AgMBAAECggEAVFVqZoN4QumSYBKVUYOX0AAp2ygflC6gnPWkeo39bjB5
jiM4WcNacMtIvq5JoYBANx2BUSfd/PRf+ierOPrLrA7UuYJLwALJyA0h71kVCLN+
FC0Il/bIF5nU+mt/cBfI8y9ELVtEFh6GVeQFxQxlil7fCZ1f4TKQ6XsJI1/3sU2P
hbOuyfKKiWym8n5BV6NP3gotjnT01I+seplx3oMOKIaGl0KMgkuU2r8o8WMjA7Gx
1WWPJDpUdyYDYSUH8PubXowHkE+2RXddZ+tGvS8mF/A4Q0hdj2T9XvzyZ813O9Tv
n522A9QQE8YlqwAYh4z3VoNhz+Fi1mQfYsIblNygSQKBgQDrk+kB/dz92RPhP/rh
zAOvwRuI2TOaw98kdgpVlb6gMVmN2EWkzkdnwQDJhV+MFZob4wi+TpsDPv4fjubq
gqbM/MYc0kNtIEA4GkIJLCK5Hh7c6kCQfya+/eq4Ju6C3+I4R46/+9E7ixA83Zjf
ftqTlYOrlMby84Lvsf81LtiMiQKBgQDaFzXpDBPOIaup68k9NeZyXHKI8wNQXkui
JyjM9A3U2D8O9Yty8G+Oq0B4oUGlyenMGJiQmf3bAffJBkLCMXCGXYD8CCKsiSJ6
R6XBfbpPkzCwl67FFN/8Z0nxZ0lbxd2ZMTC4qxH4peD5TNZM89kTpSNXPrr55zzm
qREmxisZvwKBgQCNK3jBScjpkfFY1UdZkjFPXDBM5KQJBYGtztLIkNDIHGqnFsg9
R6QAp+b53GPyhWtxdK7jpCU+X7xXWwJD3AFq67sowFPJjD8Pn6Sc7IbuWf9ysSn5
rUihwXWr3yCk6tcclL0VjSjIPsB/SOf4XoNLV5is9J34Lzbyvr7JtwXryQKBgQCM
m3xRdUzrkD/J/M+w3ChoQPxDGVJgpXrj35Vplku4l3cIYPz4LNXvyK93VpgpmGVZ
Bd6PFAlcAwfLHnM6Gn/u0SgQ1fns/TkyVzEh77qIBWDV6eVvAQdsBvfgYPQl7Arz
8ofz969NfTzv3j8oO+sPxF9lp3cLGa/lEsmREyDEpwKBgQCvW+NK93oajo358gKh
/xfSv7yMiSL26NcIgHmQouZVXJ3Dg0KSISx8tgY0/7TwC2mPa0Ryhpb/3HtAIXoY
eqkQGHqnC4voxSoati667mMGdHL1+12WvQmhfTLCWmZ5ccNlR+aFD20TGbMxnejS
XnARctVkIcUYORcYwvuu9meDkw==
-----END PRIVATE KEY-----
`

	priv, err := PrivateKeyFromPKCS8PEM(pem)
	require.NoError(t, err)

	rt := priv.ToPKCS8PEM()
	require.Equal(t, pem, rt)
}

func TestSignatureASN1(t *testing.T) {
	// openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
	// openssl pkey -in private.pem -pubout -out public.pem
	// echo -n "message" | openssl dgst -sha256 -sign private.pem -out signature.der
	// echo -n "message" | openssl dgst -sha256 -verify public.pem -signature signature.der

	pubPem := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmtKXCTkUDcKbZGsEEUTo
16xblCyh6zmA8pXVGgmC66QiTNdKzxdwTykXTDs9sEre9ea34h2M7dwrA1weAmBu
grAXe0QmIXIqjFKRKdfty09yWVtKF7FGwEMlhKftWC225R+tRuLwbKG4cCSzHxcf
JfqCYqGDM7BrF39ilQzFYw5sUiWn3ppRPWa2oEV3cw19zFnHMbEHIQIdFyCcIv5x
GUSJ6sJVp0YvsODsZbA+Zyb2UMRfXD8fDHm9bJQCY0x/wGJLfvJmWtZLciwc145U
BN3SezY30NviZtZBKWjXgb6gL69L94U10/8ghmA30DY7bKs4+/7R2nOw91CO4rCo
1QIDAQAB
-----END PUBLIC KEY-----
`
	pub, err := PublicKeyFromX509PEM(pubPem)
	require.NoError(t, err)

	b64sig := `BdvBkZWxIVE2mfM48H1WlOs3k9NzyS4oUxAMOZWNNTYDU6+DLbhZ7Hnt3rRKX3m6f1cX5DCsHcPC
6sNtsR8Xp9u09GWCN/K28fF7Pcl0E87MdhAUL7jKNK5bb1XWx/GCUmoKXRZiR/gA10iB2Lmjd1MC
HItTCig91gmFm5PO67u9yM+cqE2nGyOh13/kT5Np9MUyaE9dkjoQGum23Ta6m7v0atWsPhO5aVVI
76vLwGhYAhQe22RxBlPRXyRInr0EnVgHQOe211o//erPZYQAm+N1kK+yjV8NbPxJX+r5sYUE19NL
MCB+kOgWk51uJwuiuHlffGMBPxku/t+skxI7Bw==`
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	require.NoError(t, err)

	require.True(t, pub.VerifyASN1([]byte("message"), sig))
}

func TestPublicKeyPKCS1RoundTrip(t *testing.T) {
	pub, _, err := GenerateKeyPair(2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PublicKey(pub.Unwrap())
	rt, err := PublicKeyFromPKCS1DER(der)
	require.NoError(t, err)
	require.True(t, pub.Equal(rt))
}

func TestRejectBelowPolicyRSAImports(t *testing.T) {
	weak, err := stdrsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	pkixDER, err := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	require.NoError(t, err)
	pkixPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: pkixDER,
	}))
	pkcs1DER := x509.MarshalPKCS1PublicKey(&weak.PublicKey)
	publicKeyMultibase := helpers.PublicKeyMultibaseEncode(MultibaseCode, pkixDER)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(weak)
	require.NoError(t, err)
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: pkcs8DER,
	}))

	n := weak.N.Bytes()
	e := big.NewInt(int64(weak.E)).Bytes()
	d := weak.D.Bytes()
	p := weak.Primes[0].Bytes()
	q := weak.Primes[1].Bytes()

	for _, tc := range []struct {
		name      string
		importKey func() error
	}{
		{
			name: "GenerateKeyPair",
			importKey: func() error {
				_, _, err := GenerateKeyPair(1024)
				return err
			},
		},
		{
			name: "PublicKeyFromNE",
			importKey: func() error {
				_, err := PublicKeyFromNE(n, e)
				return err
			},
		},
		{
			name: "PublicKeyFromPublicKeyMultibase",
			importKey: func() error {
				_, err := PublicKeyFromPublicKeyMultibase(publicKeyMultibase)
				return err
			},
		},
		{
			name: "PublicKeyFromX509DER",
			importKey: func() error {
				_, err := PublicKeyFromX509DER(pkixDER)
				return err
			},
		},
		{
			name: "PublicKeyFromPKCS1DER",
			importKey: func() error {
				_, err := PublicKeyFromPKCS1DER(pkcs1DER)
				return err
			},
		},
		{
			name: "PublicKeyFromX509PEM",
			importKey: func() error {
				_, err := PublicKeyFromX509PEM(pkixPEM)
				return err
			},
		},
		{
			name: "PrivateKeyFromNEDPQ",
			importKey: func() error {
				_, err := PrivateKeyFromNEDPQ(n, e, d, p, q)
				return err
			},
		},
		{
			name: "PrivateKeyFromPKCS8DER",
			importKey: func() error {
				_, err := PrivateKeyFromPKCS8DER(pkcs8DER)
				return err
			},
		},
		{
			name: "PrivateKeyFromPKCS8PEM",
			importKey: func() error {
				_, err := PrivateKeyFromPKCS8PEM(pkcs8PEM)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, tc.importKey())
		})
	}
}

func TestPublicKeyFromNERoundTrip(t *testing.T) {
	pub, _, err := GenerateKeyPair(2048)
	require.NoError(t, err)

	rt, err := PublicKeyFromNE(pub.NBytes(), pub.EBytes())
	require.NoError(t, err)
	require.True(t, pub.Equal(rt))
}

func TestPrivateKeyFromNEDPQRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair(2048)
	require.NoError(t, err)

	rt, err := PrivateKeyFromNEDPQ(pub.NBytes(), pub.EBytes(), priv.DBytes(), priv.PBytes(), priv.QBytes())
	require.NoError(t, err)
	require.True(t, priv.Equal(rt))
	require.True(t, pub.Equal(rt.Public()))
}

func TestRejectWeirdPublicKeyInputs(t *testing.T) {
	// Reuse a known-good 2048-bit modulus so each case changes only the input under test.
	validModulus, err := base64.RawURLEncoding.DecodeString("sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4RCR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjVk_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCaexFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ")
	require.NoError(t, err)

	evenModulus := append([]byte{}, validModulus...)
	evenModulus[len(evenModulus)-1] &^= 1

	// Build a 8193-bit odd modulus to exceed the package's 8192-bit upper bound.
	tooLargeModulus := make([]byte, 1025)
	tooLargeModulus[0] = 0x80
	tooLargeModulus[len(tooLargeModulus)-1] = 0x01

	// This is 2^63, which does not fit in a signed int64 and must be rejected.
	exponentTooLarge := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	for _, tc := range []struct {
		name string
		n    []byte
		e    []byte
	}{
		{
			name: "empty modulus",
			n:    nil,
			e:    []byte{0x03},
		},
		{
			name: "too small modulus",
			n:    validModulus[:len(validModulus)-1],
			e:    []byte{0x03},
		},
		{
			name: "too large modulus",
			n:    tooLargeModulus,
			e:    []byte{0x03},
		},
		{
			name: "even modulus",
			n:    evenModulus,
			e:    []byte{0x03},
		},
		{
			name: "empty exponent",
			n:    validModulus,
			e:    nil,
		},
		{
			name: "exponent one",
			n:    validModulus,
			e:    []byte{0x01},
		},
		{
			name: "even exponent",
			n:    validModulus,
			e:    []byte{0x02},
		},
		{
			name: "exponent too large",
			n:    validModulus,
			e:    exponentTooLarge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PublicKeyFromNE(tc.n, tc.e)
			require.Error(t, err)
		})
	}
}
