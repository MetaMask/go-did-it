package x25519

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto/_testsuite"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "x25519",
	GenerateKeyPair:                 GenerateKeyPair,
	PublicKeyFromBytes:              PublicKeyFromBytes,
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromBytes:             PrivateKeyFromBytes,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	PublicKeyBytesSize:              PublicKeyBytesSize,
	PrivateKeyBytesSize:             PrivateKeyBytesSize,
	SignatureBytesSize:              -1,
}

func TestSuite(t *testing.T) {
	testsuite.TestSuite(t, harness)
}

func BenchmarkSuite(b *testing.B) {
	testsuite.BenchSuite(b, harness)
}

func TestEd25519ToX25519(t *testing.T) {
	// Known pubkey ed25519 --> x25519
	for _, tc := range []struct {
		pubEdMultibase string
		pubXMultibase  string
	}{
		{
			// From https://w3c-ccg.github.io/did-key-spec/#ed25519-with-x25519
			pubEdMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			pubXMultibase:  "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
		},
	} {
		t.Run(tc.pubEdMultibase, func(t *testing.T) {
			pubEd, err := ed25519.PublicKeyFromPublicKeyMultibase(tc.pubEdMultibase)
			require.NoError(t, err)
			pubX, err := PublicKeyFromEd25519(pubEd)
			require.NoError(t, err)
			require.Equal(t, tc.pubXMultibase, pubX.ToPublicKeyMultibase())
		})
	}

	// Check that ed25519 --> x25519 match for pubkeys and privkeys
	t.Run("ed25519 --> x25519 priv+pub are matching", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			pubEd, privEd, err := ed25519.GenerateKeyPair()
			require.NoError(t, err)

			pubX, err := PublicKeyFromEd25519(pubEd)
			require.NoError(t, err)
			privX, err := PrivateKeyFromEd25519(privEd)
			require.NoError(t, err)

			require.True(t, pubX.Equal(privX.Public()))
		}
	})
}

func TestPublicKeyFromEd25519EdgeCases(t *testing.T) {
	// Ed25519 public keys are encoded as 32 little-endian bytes where bits 0-254
	// carry the y coordinate and bit 255 is the sign of x (cleared before conversion).
	//
	// p = 2^255 - 19 in little-endian:
	//   big-endian:    7F FF ... FF ED
	//   little-endian: ED FF ... FF 7F
	//
	// All cases below must be rejected by PublicKeyFromEd25519.
	cases := []struct {
		name string
		// 32-byte little-endian encoding of y (sign bit may be set; it is cleared
		// inside PublicKeyFromEd25519 before use).
		yLE [32]byte
	}{
		{
			// y = 1 → denominator (1 - y) = 0, Birational map undefined.
			name: "y=1 denominator zero",
			yLE:  [32]byte{0x01},
		},
		{
			// y = p-1 ≡ -1 (mod p) → numerator (1 + y) ≡ 0 (mod p), u = 0 (low-order point).
			// This was the dead guard: previously compared against Go integer -1,
			// which SetBytes can never produce.
			name: "y=p-1 low-order point",
			yLE: [32]byte{
				0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
			},
		},
		{
			// y = p → non-canonical encoding; (1 - y) = 1 - p = -(p-1),
			// which is coprime to p, so this wouldn't panic, but the encoding is invalid.
			name: "y=p non-canonical",
			yLE: [32]byte{
				0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
			},
		},
		{
			// y = p+1 ≡ 1 (mod p) → non-canonical encoding of y=1.
			// (1 - y) = -p, a multiple of p; ModInverse returns nil → panic without the y>=p guard.
			name: "y=p+1 non-canonical alias of y=1",
			yLE: [32]byte{
				0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := ed25519.PublicKeyFromBytes(tc.yLE[:])
			require.NoError(t, err)
			_, err = PublicKeyFromEd25519(pub)
			require.Error(t, err)
		})
	}
}
