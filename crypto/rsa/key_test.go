package rsa

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did/crypto/_testsuite"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "rsa-2048",
	GenerateKeyPair:                 func() (*PublicKey, *PrivateKey, error) { return GenerateKeyPair(2048) },
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	SignatureBytesSize:              123456,
}

func TestSuite(t *testing.T) {
	testsuite.TestSuite(t, harness)
}

func BenchmarkSuite(b *testing.B) {
	testsuite.BenchSuite(b, harness)
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
