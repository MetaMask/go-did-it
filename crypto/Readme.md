# Crypto package

This crypto package is a thin ergonomic layer on top of the normal golang crypto packages or `x/crypto`.

It aims to solve the following problems with the standard crypto packages:
- different algorithms have different APIs and ergonomics, which makes it hard to use them interchangeably
- occasionally, it's quite hard to figure out how to do simple tasks (like encoding/decoding keys)
- it's still necessary to make some educated choices (e.g. which hash function to use for signatures)
- sometimes features are left out (e.g. ed25519 to X25519 for key exchange, secp256k1...)
- some hash functions are not available in the standard library with no easy way to extend it (e.g. KECCAK-256)

To do so, this package provides and implements a set of shared interfaces for all algorithms. As not all algorithms
support all features (e.g. RSA keys don't support key exchange), some interfaces are optionally implemented.

An additional benefit of shared interfaces is that a shared test suite can be written to test all algorithms, which this
package does.

Note: this is not a dig or a criticism of the golang crypto packages, just an attempt to make them easier to use.

## Example

```go
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
```

## Supported Cryptographic Algorithms

| Algorithm       | Signature Format  | Public Key Formats                  | Private Key Formats       | Key Agreement  |
|-----------------|-------------------|-------------------------------------|---------------------------|----------------|
| Ed25519         | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM | ✅ (via X25519) |
| ECDSA P-256     | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM | ✅              |
| ECDSA P-384     | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM | ✅              |
| ECDSA P-521     | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM | ✅              |
| ECDSA secp256k1 | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM | ✅              |
| RSA             | PKCS#1 v1.5 ASN.1 | X.509 DER/PEM, Multibase            | PKCS#8 DER/PEM            | ❌              |
| X25519          | ❌                 | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM | ✅              |
