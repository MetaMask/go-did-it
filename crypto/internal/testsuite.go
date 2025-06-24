package helpers

import (
	"fmt"
	"strings"
	"testing"
	"text/tabwriter"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did/crypto"
)

type TestHarness[PubT crypto.PublicKey, PrivT crypto.PrivateKey] struct {
	Name string

	GenerateKeyPair func() (PubT, PrivT, error)

	PublicKeyFromBytes              func(b []byte) (PubT, error)
	PublicKeyFromPublicKeyMultibase func(multibase string) (PubT, error)
	PublicKeyFromX509DER            func(bytes []byte) (PubT, error)
	PublicKeyFromX509PEM            func(str string) (PubT, error)

	PrivateKeyFromBytes    func(b []byte) (PrivT, error)
	PrivateKeyFromPKCS8DER func(bytes []byte) (PrivT, error)
	PrivateKeyFromPKCS8PEM func(str string) (PrivT, error)

	MultibaseCode uint64

	PublicKeyBytesSize  int
	PrivateKeyBytesSize int
	SignatureBytesSize  int
}

func TestSuite[PubT crypto.PublicKey, PrivT crypto.PrivateKey](t *testing.T, harness TestHarness[PubT, PrivT]) {
	stats := struct {
		bytesPubSize  int
		bytesPrivSize int

		x509DerPubSize   int
		pkcs8DerPrivSize int

		x509PemPubSize   int
		pkcs8PemPrivSize int

		sigRawSize  int
		sigAsn1Size int
	}{}

	t.Cleanup(func() {
		out := strings.Builder{}

		out.WriteString("\nKeypairs (in bytes):\n")
		w := tabwriter.NewWriter(&out, 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintln(w, "\tPublic key\tPrivate key")
		_, _ = fmt.Fprintf(w, "Bytes\t%v\t%v\n", stats.bytesPubSize, stats.bytesPrivSize)
		_, _ = fmt.Fprintf(w, "DER (pub:x509, priv:PKCS#8)\t%v\t%v\n", stats.x509DerPubSize, stats.pkcs8DerPrivSize)
		_, _ = fmt.Fprintf(w, "PEM (pub:x509, priv:PKCS#8)\t%v\t%v\n", stats.x509PemPubSize, stats.pkcs8PemPrivSize)
		_ = w.Flush()

		out.WriteString("\nSignatures (in bytes):\n")
		w.Init(&out, 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintln(w, "Raw bytes\tASN.1")
		_, _ = fmt.Fprintf(w, "%v\t%v\n", stats.sigRawSize, stats.sigAsn1Size)
		_ = w.Flush()

		t.Logf("Test result for %s:\n%s\n", harness.Name, out.String())
	})

	t.Run("GenerateKeyPair", func(t *testing.T) {
		pub, priv, err := harness.GenerateKeyPair()
		require.NoError(t, err)
		require.NotNil(t, pub)
		require.NotNil(t, priv)
		require.True(t, pub.Equal(priv.Public()))
	})

	t.Run("Equality", func(t *testing.T) {
		pub1, priv1, err := harness.GenerateKeyPair()
		require.NoError(t, err)
		pub2, priv2, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		require.True(t, pub1.Equal(pub1))
		require.True(t, priv1.Equal(priv1))
		require.False(t, pub1.Equal(pub2))
		require.False(t, priv1.Equal(priv2))

		pub1copy, err := harness.PublicKeyFromBytes(pub1.ToBytes())
		require.NoError(t, err)
		require.True(t, pub1.Equal(pub1copy))
		require.True(t, pub1copy.Equal(pub1))

		priv1copy, err := harness.PrivateKeyFromBytes(priv1.ToBytes())
		require.NoError(t, err)
		require.True(t, priv1.Equal(priv1copy))
		require.True(t, priv1copy.Equal(priv1))
	})

	t.Run("BytesRoundTrip", func(t *testing.T) {
		pub, priv, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		bytes := pub.ToBytes()
		stats.bytesPubSize = len(bytes)
		rtPub, err := harness.PublicKeyFromBytes(bytes)
		require.NoError(t, err)
		require.True(t, pub.Equal(rtPub))
		require.Equal(t, harness.PublicKeyBytesSize, len(bytes))

		bytes = priv.ToBytes()
		stats.bytesPrivSize = len(bytes)
		rtPriv, err := harness.PrivateKeyFromBytes(bytes)
		require.NoError(t, err)
		require.True(t, priv.Equal(rtPriv))
		require.Equal(t, harness.PrivateKeyBytesSize, len(bytes))
	})

	t.Run("MultibaseRoundTrip", func(t *testing.T) {
		pub, _, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		mb := pub.ToPublicKeyMultibase()
		rt, err := harness.PublicKeyFromPublicKeyMultibase(mb)
		require.NoError(t, err)
		require.Equal(t, pub, rt)

		encoding, bytes, err := mbase.Decode(mb)
		require.NoError(t, err)
		require.Equal(t, mbase.Base58BTC, int32(encoding)) // according to the DID spec
		code, _, err := varint.FromUvarint(bytes)
		require.NoError(t, err)
		require.Equal(t, harness.MultibaseCode, code)
	})

	t.Run("PublicKeyX509RoundTrip", func(t *testing.T) {
		pub, _, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		der := pub.ToX509DER()
		stats.x509DerPubSize = len(der)
		rt, err := harness.PublicKeyFromX509DER(der)
		require.NoError(t, err)
		require.True(t, pub.Equal(rt))

		pem := pub.ToX509PEM()
		stats.x509PemPubSize = len(pem)
		rt, err = harness.PublicKeyFromX509PEM(pem)
		require.NoError(t, err)
		require.True(t, pub.Equal(rt))
	})

	t.Run("PrivateKeyPKCS8RoundTrip", func(t *testing.T) {
		pub, priv, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		der := priv.ToPKCS8DER()
		stats.pkcs8DerPrivSize = len(der)
		rt, err := harness.PrivateKeyFromPKCS8DER(der)
		require.NoError(t, err)
		require.True(t, priv.Equal(rt))
		require.True(t, pub.Equal(rt.Public()))

		pem := priv.ToPKCS8PEM()
		stats.pkcs8PemPrivSize = len(pem)
		rt, err = harness.PrivateKeyFromPKCS8PEM(pem)
		require.NoError(t, err)
		require.True(t, priv.Equal(rt))
		require.True(t, pub.Equal(rt.Public()))
	})

	t.Run("Signature", func(t *testing.T) {
		pub, priv, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		spub, ok := (crypto.PublicKey(pub)).(crypto.SigningPublicKey)
		if !ok {
			t.Skip("Signature is not implemented")
		}
		spriv, ok := (crypto.PrivateKey(priv)).(crypto.SigningPrivateKey)
		if !ok {
			t.Skip("Signature is not implemented")
		}

		for _, tc := range []struct {
			name         string
			signer       func(msg []byte) ([]byte, error)
			verifier     func(msg []byte, sig []byte) bool
			expectedSize int
			stats        *int
		}{
			{
				name:         "Bytes signature",
				signer:       spriv.SignToBytes,
				verifier:     spub.VerifyBytes,
				expectedSize: harness.SignatureBytesSize,
				stats:        &stats.sigRawSize,
			},
			{
				name:     "ASN.1 signature",
				signer:   spriv.SignToASN1,
				verifier: spub.VerifyASN1,
				stats:    &stats.sigAsn1Size,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				msg := []byte("message")

				sig, err := tc.signer(msg)
				require.NoError(t, err)
				require.NotEmpty(t, sig)

				if tc.expectedSize > 0 {
					require.Equal(t, tc.expectedSize, len(sig))
				}
				*tc.stats = len(sig)

				valid := tc.verifier(msg, sig)
				require.True(t, valid)

				valid = tc.verifier([]byte("wrong message"), sig)
				require.False(t, valid)
			})
		}
	})

	t.Run("KeyExchange", func(t *testing.T) {
		pub1, priv1, err := harness.GenerateKeyPair()
		require.NoError(t, err)
		pub2, priv2, err := harness.GenerateKeyPair()
		require.NoError(t, err)
		pub3, _, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		kePriv1, ok := crypto.PrivateKey(priv1).(crypto.KeyExchangePrivateKey)
		if !ok {
			t.Skip("Key exchange is not implemented")
		}
		kePriv2 := crypto.PrivateKey(priv2).(crypto.KeyExchangePrivateKey)

		// TODO: test with incompatible public keys
		require.True(t, kePriv1.PublicKeyIsCompatible(pub2))
		require.True(t, kePriv2.PublicKeyIsCompatible(pub1))

		// 1 --> 2
		kA, err := kePriv1.KeyExchange(pub2)
		require.NoError(t, err)
		require.NotEmpty(t, kA)
		// 2 --> 1
		kB, err := kePriv2.KeyExchange(pub1)
		require.NoError(t, err)
		require.NotEmpty(t, kB)
		// 2 --> 3
		kC, err := kePriv2.KeyExchange(pub3)
		require.NoError(t, err)
		require.NotEmpty(t, kC)

		require.Equal(t, kA, kB)
		require.NotEqual(t, kB, kC)
	})
}

func BenchSuite[PubT crypto.PublicKey, PrivT crypto.PrivateKey](b *testing.B, harness TestHarness[PubT, PrivT]) {
	b.Run("GenerateKeyPair", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _, _ = harness.GenerateKeyPair()
		}
	})

	b.Run("Bytes", func(b *testing.B) {
		b.Run("PubToBytes", func(b *testing.B) {
			pub, _, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = pub.ToBytes()
			}
		})

		b.Run("PubFromBytes", func(b *testing.B) {
			pub, _, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			buf := pub.ToBytes()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = harness.PublicKeyFromBytes(buf)
			}
		})

		b.Run("PrivToBytes", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = priv.ToBytes()
			}
		})

		b.Run("PrivFromBytes", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			buf := priv.ToBytes()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = harness.PrivateKeyFromBytes(buf)
			}
		})
	})

	b.Run("DER", func(b *testing.B) {
		b.Run("PubToDER", func(b *testing.B) {
			pub, _, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = pub.ToX509DER()
			}
		})

		b.Run("PubFromDER", func(b *testing.B) {
			pub, _, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			buf := pub.ToX509DER()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = harness.PublicKeyFromX509DER(buf)
			}
		})

		b.Run("PrivToDER", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = priv.ToPKCS8DER()
			}
		})

		b.Run("PrivFromDER", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			buf := priv.ToPKCS8DER()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = harness.PrivateKeyFromPKCS8DER(buf)
			}
		})
	})

	b.Run("PEM", func(b *testing.B) {
		b.Run("PubToPEM", func(b *testing.B) {
			pub, _, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = pub.ToX509PEM()
			}
		})

		b.Run("PubFromPEM", func(b *testing.B) {
			pub, _, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			buf := pub.ToX509PEM()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = harness.PublicKeyFromX509PEM(buf)
			}
		})

		b.Run("PrivToPEM", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = priv.ToPKCS8PEM()
			}
		})

		b.Run("PrivFromPEM", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			buf := priv.ToPKCS8PEM()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = harness.PrivateKeyFromPKCS8PEM(buf)
			}
		})
	})

	b.Run("Signatures", func(b *testing.B) {
		if _, ok := (crypto.PublicKey(*new(PubT))).(crypto.SigningPublicKey); !ok {
			b.Skip("Signature is not implemented")
		}

		b.Run("Sign to Bytes signature", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)

			spriv := (crypto.PrivateKey(priv)).(crypto.SigningPrivateKey)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, _ = spriv.SignToBytes([]byte("message"))
			}
		})

		b.Run("Verify from Bytes signature", func(b *testing.B) {
			pub, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)

			spub := (crypto.PublicKey(pub)).(crypto.SigningPublicKey)
			spriv := (crypto.PrivateKey(priv)).(crypto.SigningPrivateKey)
			sig, err := spriv.SignToBytes([]byte("message"))
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				spub.VerifyBytes([]byte("message"), sig)
			}
		})

		b.Run("Sign to ASN.1 signature", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)

			spriv := (crypto.PrivateKey(priv)).(crypto.SigningPrivateKey)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, _ = spriv.SignToASN1([]byte("message"))
			}
		})

		b.Run("Verify from ASN.1 signature", func(b *testing.B) {
			pub, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)

			spub := (crypto.PublicKey(pub)).(crypto.SigningPublicKey)
			spriv := (crypto.PrivateKey(priv)).(crypto.SigningPrivateKey)
			sig, err := spriv.SignToASN1([]byte("message"))
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				spub.VerifyASN1([]byte("message"), sig)
			}
		})
	})

	b.Run("Key exchange", func(b *testing.B) {
		if _, ok := (crypto.PrivateKey(*new(PrivT))).(crypto.KeyExchangePrivateKey); !ok {
			b.Skip("Key echange is not implemented")
		}

		b.Run("KeyExchange", func(b *testing.B) {
			_, priv1, err := harness.GenerateKeyPair()
			require.NoError(b, err)
			kePriv1 := (crypto.PrivateKey(priv1)).(crypto.KeyExchangePrivateKey)
			pub2, _, err := harness.GenerateKeyPair()
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, _ = kePriv1.KeyExchange(pub2)
			}
		})
	})
}
