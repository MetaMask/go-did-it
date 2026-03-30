package secp256k1

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/_testsuite"
	"github.com/MetaMask/go-did-it/crypto/secp256k1/testvectors"
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

func TestSignToCompact(t *testing.T) {
	messages := [][]byte{
		[]byte("hello"),
		[]byte(""),
		make([]byte, 1024),
	}

	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.KECCAK_256} {
		t.Run(hash.String(), func(t *testing.T) {
			pub, priv, err := GenerateKeyPair()
			require.NoError(t, err)

			for _, msg := range messages {
				sig := priv.SignToCompact(msg, crypto.WithSigningHash(hash))
				require.Len(t, sig, 65, "compact signature must be 65 bytes")
				// dcrd encodes the recovery flag as 27+4+bit for compressed keys (31 or 32).
				require.Contains(t, []byte{31, 32}, sig[0], "recovery flag must be 31 or 32")

				// Hash the message the same way SignToCompact does.
				hasher := hash.New()
				hasher.Write(msg)
				msgHash := hasher.Sum(nil)

				// The recovered key must match the signer's public key.
				recovered, err := PublicKeyFromRecovery(sig, msgHash)
				require.NoError(t, err)
				require.True(t, pub.Equal(recovered), "recovered key must match original")

				// The r||s portion (bytes 1..65) must also pass VerifyBytes.
				require.True(t, pub.VerifyBytes(msg, sig[1:], crypto.WithSigningHash(hash)),
					"raw r||s portion must verify")
			}
		})
	}
}

func TestPublicKeyFromCompactRecovery(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("test message")
	hasher := crypto.SHA256.New()
	hasher.Write(message)
	hash := hasher.Sum(nil)

	// SignCompact produces a 65-byte compact signature with the recovery flag prepended.
	compactSig := ecdsa.SignCompact(priv.Unwrap(), hash, true)
	require.Len(t, compactSig, 65)

	recovered, err := PublicKeyFromRecovery(compactSig, hash)
	require.NoError(t, err)
	require.True(t, pub.Equal(recovered))
}

func TestSignatureASN1(t *testing.T) {
	// openssl ecparam -genkey -name secp256k1 -noout -out private.pem
	// openssl ec -in private.pem -pubout -out public.pem
	// echo -n "message" | openssl dgst -sha256 -sign private.pem -out signature.der
	// echo -n "message" | openssl dgst -sha256 -verify public.pem -signature signature.der

	pubPem := `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEszL1+ZFqUMAHjLAyzMW7xMBPZek/8cNj
1qI7EgQooB3f8Sh7JwvXu8cosRnjjvYVvS7OliRsbvuceCQ7HBC4fA==
-----END PUBLIC KEY-----
`
	pub, err := PublicKeyFromX509PEM(pubPem)
	require.NoError(t, err)

	b64sig := `MEYCIQDv5SLy768FbOafzDlrxIeeoEn7tKpYBSK6WcKaOZ6AJAIhAKXV6VAwiPq4uk9TpGyFN5JK
8jZPrQ7hdRR5veKKDX2w`
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	require.NoError(t, err)

	require.True(t, pub.VerifyASN1([]byte("message"), sig))
}

func TestWycheproofVerifyASN1(t *testing.T) {
	all, err := testvectors.LoadECDSA()
	require.NoError(t, err)

	for _, v := range all {
		t.Run(fmt.Sprintf("%d-%s", v.TcId, v.Comment), func(t *testing.T) {
			x, err := hex.DecodeString(v.WX)
			require.NoError(t, err)
			y, err := hex.DecodeString(v.WY)
			require.NoError(t, err)

			pub, err := PublicKeyFromXY(x, y)
			require.NoError(t, err)

			msg, _ := hex.DecodeString(v.Msg)
			sig, _ := hex.DecodeString(v.Sig)

			got := pub.VerifyASN1(msg, sig)

			switch v.Result {
			case "valid":
				require.True(t, got, "tcId=%d: expected valid signature to verify", v.TcId)
			case "invalid":
				require.False(t, got, "tcId=%d: expected invalid signature to be rejected", v.TcId)
			}
			// "acceptable" — implementation-defined; just check for no panic
		})
	}
}

func TestWycheproofVerifyBytes(t *testing.T) {
	all, err := testvectors.LoadECDSA()
	require.NoError(t, err)

	// Only select vectors that test DER-decodable signatures so we can extract
	// raw r||s. BerEncodedSignature vectors will fail DER parsing, which is fine
	// since VerifyBytes doesn't accept DER anyway.
	vectors := testvectors.SelectECDSA(all,
		"ValidSignature", "RangeCheck", "InvalidSignature", "ModifiedSignature",
	)

	for _, v := range vectors {
		t.Run(fmt.Sprintf("%d-%s", v.TcId, v.Comment), func(t *testing.T) {
			x, err := hex.DecodeString(v.WX)
			require.NoError(t, err)
			y, err := hex.DecodeString(v.WY)
			require.NoError(t, err)

			pub, err := PublicKeyFromXY(x, y)
			require.NoError(t, err)

			msg, _ := hex.DecodeString(v.Msg)
			sigDER, _ := hex.DecodeString(v.Sig)

			parsed, err := ecdsa.ParseDERSignature(sigDER)
			if err != nil {
				// DER parsing failed; for valid vectors this is a test failure.
				require.NotEqual(t, "valid", v.Result,
					"tcId=%d: valid vector failed DER parse: %v", v.TcId, err)
				return
			}

			r := parsed.R()
			s := parsed.S()
			var rawSig [SignatureBytesSize]byte
			rBytes := r.Bytes()
			sBytes := s.Bytes()
			copy(rawSig[:32], rBytes[:])
			copy(rawSig[32:], sBytes[:])

			got := pub.VerifyBytes(msg, rawSig[:])

			switch v.Result {
			case "valid":
				require.True(t, got, "tcId=%d: expected valid signature to verify", v.TcId)
			case "invalid":
				require.False(t, got, "tcId=%d: expected invalid signature to be rejected", v.TcId)
			}
		})
	}
}

func TestWycheproofPublicKeyFromXY(t *testing.T) {
	all, err := testvectors.LoadECDSA()
	require.NoError(t, err)

	// Collect unique public keys from all vectors and verify they parse cleanly.
	seen := make(map[string]bool)
	for _, v := range all {
		key := v.WX + ":" + v.WY
		if seen[key] {
			continue
		}
		seen[key] = true

		t.Run(fmt.Sprintf("wx=%s...wy=%s...", v.WX[:8], v.WY[:8]), func(t *testing.T) {
			x, err := hex.DecodeString(v.WX)
			require.NoError(t, err)
			y, err := hex.DecodeString(v.WY)
			require.NoError(t, err)

			_, err = PublicKeyFromXY(x, y)
			require.NoError(t, err)
		})
	}

	// Hand-crafted off-curve points must be rejected.
	offCurve := []struct {
		name string
		x, y string
	}{
		// x=1, y=1 is not on secp256k1
		{"(1,1)", "0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000000000001"},
		// Generator x, wrong y (generator y + 1)
		{"(Gx, Gy+1)", "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
			"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B9"},
	}

	for _, tc := range offCurve {
		t.Run("off-curve/"+tc.name, func(t *testing.T) {
			x, _ := hex.DecodeString(tc.x)
			y, _ := hex.DecodeString(tc.y)
			_, err := PublicKeyFromXY(x, y)
			require.Error(t, err, "off-curve point should be rejected")
		})
	}
}
