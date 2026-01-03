package crypto_test

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/ucan-wg/go-varsig"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/p256"
)

func Example() {
	// This example demonstrates how to use the crypto package without going over all the features.
	// We will use P-256 keys, but they all work the same way (although not all have all the features).

	// 0: Generate a key pair
	pubAlice, privAlice, err := p256.GenerateKeyPair()
	handleErr(err)

	// 1: Serialize a key, read it back, verify it's the same
	privAliceBytes := privAlice.ToPKCS8DER()
	privAlice2, err := p256.PrivateKeyFromPKCS8DER(privAliceBytes)
	handleErr(err)
	fmt.Println("Keys are equals:", privAlice.Equal(privAlice2))

	// 2: Sign a message, verify the signature.
	// Signatures can be made in raw bytes (SignToBytes) or ASN.1 DER format (SignToASN1).
	msg := []byte("hello world")
	sig, err := privAlice.SignToBytes(msg)
	handleErr(err)
	fmt.Println("Signature is valid:", pubAlice.VerifyBytes(msg, sig))

	// 3: Signatures are done with an opinionated default configuration, but you can override it.
	// For example, the default hash function for P-256 is SHA-256, but you can use SHA-384 instead.
	opts := []crypto.SigningOption{crypto.WithSigningHash(crypto.SHA384)}
	sig384, err := privAlice.SignToBytes(msg, opts...)
	handleErr(err)
	fmt.Println("Signature is valid (SHA-384):", pubAlice.VerifyBytes(msg, sig384, opts...))

	// 4: Key exchange: generate a second key-pair and compute a shared secret.
	// ⚠️ Security Warning: The shared secret returned by key agreement should NOT be used directly as an encryption key.
	// It must be processed through a Key Derivation Function (KDF) such as HKDF before being used in cryptographic protocols.
	// Using the raw shared secret directly can lead to security vulnerabilities.
	pubBob, privBob, err := p256.GenerateKeyPair()
	handleErr(err)
	shared1, err := privAlice.KeyExchange(pubBob)
	handleErr(err)
	shared2, err := privBob.KeyExchange(pubAlice)
	handleErr(err)
	fmt.Println("Shared secrets are identical:", bytes.Equal(shared1, shared2))

	// 5: Bonus: one very annoying thing in cryptographic protocols is that the other side needs to know the configuration
	// you used for your signature. Having defaults or implied config only work sor far.
	// To solve this problem, this package integrates varsig: a format to describe the signing configuration. This varsig
	// can be attached to the signature, and the other side doesn't have to guess any more. Here is how it works:
	varsigBytes := privAlice.Varsig(opts...).Encode()
	fmt.Println("Varsig:", base64.StdEncoding.EncodeToString(varsigBytes))
	sig, err = privAlice.SignToBytes(msg, opts...)
	handleErr(err)
	varsigDecoded, err := varsig.Decode(varsigBytes)
	handleErr(err)
	fmt.Println("Signature with varsig is valid:", pubAlice.VerifyBytes(msg, sig, crypto.WithVarsig(varsigDecoded)))

	// Output:
	// Keys are equals: true
	// Signature is valid: true
	// Signature is valid (SHA-384): true
	// Shared secrets are identical: true
	// Varsig: NAHsAYAkIF8=
	// Signature with varsig is valid: true
}

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}
