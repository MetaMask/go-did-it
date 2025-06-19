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

	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int
}

func TestSuite[PubT crypto.PublicKey, PrivT crypto.PrivateKey](t *testing.T, harness TestHarness[PubT, PrivT]) {
	stats := struct {
		bytesPubSize  int
		bytesPrivSize int

		x509DerPubSize   int
		pkcs8DerPrivSize int

		x509PemPubSize   int
		pkcs8PemPrivSize int
	}{}

	t.Cleanup(func() {
		out := strings.Builder{}
		w := tabwriter.NewWriter(&out, 0, 0, 3, ' ', 0)

		_, _ = fmt.Fprintln(w, "\tPublic key\tPrivate key")
		_, _ = fmt.Fprintf(w, "Bytes\t%v\t%v\n", stats.bytesPubSize, stats.bytesPrivSize)
		_, _ = fmt.Fprintf(w, "DER (pub:x509, priv:PKCS#8)\t%v\t%v\n", stats.x509DerPubSize, stats.pkcs8DerPrivSize)
		_, _ = fmt.Fprintf(w, "PEM (pub:x509, priv:PKCS#8)\t%v\t%v\n", stats.x509PemPubSize, stats.pkcs8PemPrivSize)
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

		bytes = priv.ToBytes()
		stats.bytesPrivSize = len(bytes)
		rtPriv, err := harness.PrivateKeyFromBytes(bytes)
		require.NoError(t, err)
		require.True(t, priv.Equal(rtPriv))
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

		msg := []byte("message")

		sig, err := spriv.Sign(msg)
		require.NoError(t, err)
		require.NotEmpty(t, sig)
		require.Equal(t, harness.SignatureSize, len(sig))

		valid := spub.Verify(msg, sig)
		require.True(t, valid)

		valid = spub.Verify([]byte("wrong message"), sig)
		require.False(t, valid)
	})

	t.Run("KeyExchange", func(t *testing.T) {
		pub1, priv1, err := harness.GenerateKeyPair()
		require.NoError(t, err)
		pub2, priv2, err := harness.GenerateKeyPair()
		require.NoError(t, err)

		kePub1, ok := (crypto.PublicKey(pub1)).(crypto.KeyExchangePublicKey)
		if !ok {
			t.Skip("Key exchange is not implemented")
		}
		kePub2 := (crypto.PublicKey(pub2)).(crypto.KeyExchangePublicKey)

		// TODO: test with incompatible private keys
		require.True(t, kePub1.PrivateKeyIsCompatible(priv2))
		require.True(t, kePub2.PrivateKeyIsCompatible(priv1))

		k1, err := kePub1.ECDH(priv2)
		require.NoError(t, err)
		require.NotEmpty(t, k1)
		k2, err := kePub2.ECDH(priv1)
		require.NoError(t, err)
		require.NotEmpty(t, k2)

		require.Equal(t, k1, k2)
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

		b.Run("Sign", func(b *testing.B) {
			_, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)

			spriv := (crypto.PrivateKey(priv)).(crypto.SigningPrivateKey)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				spriv.Sign([]byte("message"))
			}
		})

		b.Run("Verify", func(b *testing.B) {
			pub, priv, err := harness.GenerateKeyPair()
			require.NoError(b, err)

			spub := (crypto.PublicKey(pub)).(crypto.SigningPublicKey)
			spriv := (crypto.PrivateKey(priv)).(crypto.SigningPrivateKey)
			sig, err := spriv.Sign([]byte("message"))
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				spub.Verify([]byte("message"), sig)
			}
		})
	})

	// TODO: add key exchange benchmarks
}
