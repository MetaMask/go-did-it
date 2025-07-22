<div align="center">
  <h1 align="center">go-did-it</h1>

  <p>
    <a href="https://github.com/ucan-wg/go-did-it/tags">
        <img alt="GitHub Tag" src="https://img.shields.io/github/v/tag/ucan-wg/go-did-it">
    </a>
    <a href="https://github.com/ucan-wg/go-did-it/actions?query=">
      <img src="https://github.com/ucan-wg/go-did-it/actions/workflows/gotest.yml/badge.svg" alt="Build Status">
    </a>
    <a href="https://ucan-wg.github.io/go-did-it/dev/bench/">
        <img alt="Go benchmarks" src="https://img.shields.io/badge/Benchmarks-go-blue">
    </a>
    <a href="https://github.com/ucan-wg/go-did-it/blob/v1/LICENSE.md">
        <img alt="Apache 2.0 + MIT License" src="https://img.shields.io/badge/License-Apache--2.0+MIT-green">
    </a>
    <a href="https://pkg.go.dev/github.com/ucan-wg/go-did-it">
      <img src="https://img.shields.io/badge/Docs-godoc-blue" alt="Docs">
    </a>
  </p>
</div>

This is an implementation of Decentralized Identifiers (DIDs) in go. It differs from the alternatives in the following ways: 
- **simple**: made of shared reusable components and clear interfaces
- **fast**: while it supports DID Documents as JSON files, it's not unnecessary in the way (see below)
- **battery included**: the corresponding cryptographic handling is implemented
- **support producing and using DIDs**: unlike some others, this all-in-one implementation is meant to create, manipulate and handle DIDs
- **extensible**: you can easily register your custom DID method

Built with ❤️ by [Consensys](https://consensys.io/).

## Concepts

![`go-did-it` concepts](.github/concepts.png)

## Installation

```bash
go get github.com/ucan-wg/go-did-it
```

## Usage

### Signature verification

On the verifier (~server) side, you can parse and resolve DIDs and perform signature verification:

```go
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/ucan-wg/go-did-it"
	
	// 0) Import the methods you want to support
	_ "github.com/ucan-wg/go-did-it/verifiers/did-key"
)

func main() {
	// 1) Parse the DID string into a DID object
	d, _ := did.Parse("did:key:z6MknwcywUtTy2ADJQ8FH1GcSySKPyKDmyzT4rPEE84XREse")

	// 2) Resolve to the DID Document
	doc, _ := d.Document()

	// 3) Use the appropriate set of verification methods (ex: verify a signature for authentication purpose)
	sig, _ := base64.StdEncoding.DecodeString("nhpkr5a7juUM2eDpDRSJVdEE++0SYqaZXHtuvyafVFUx8zsOdDSrij+vHmd/ARwUOmi/ysmSD+b3K9WTBtmmBQ==")
	if ok, method := did.TryAllVerify(doc.Authentication(), []byte("message"), sig); ok {
		fmt.Println("Signature is valid, verified with method:", method.Type(), method.ID())
	} else {
		fmt.Println("Signature is invalid")
	}

	// Output: Signature is valid, verified with method: Ed25519VerificationKey2020 did:key:z6MknwcywUtTy2ADJQ8FH1GcSySKPyKDmyzT4rPEE84XREse#z6MknwcywUtTy2ADJQ8FH1GcSySKPyKDmyzT4rPEE84XREse
}
```

### Key agreement

You can also compute a shared secret to bootstrap an encrypted communication protocol.

> **⚠️ Security Warning**: The shared secret returned by key agreement should NOT be used directly as an encryption key. It must be processed through a Key Derivation Function (KDF) such as HKDF before being used in cryptographic protocols. Using the raw shared secret directly can lead to security vulnerabilities.

```go
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/ucan-wg/go-did-it"
	"github.com/ucan-wg/go-did-it/crypto/x25519"

	// 0) Import the methods you want to support
	_ "github.com/ucan-wg/go-did-it/verifiers/did-key"
)

func main() {
	// 1) We have a private key for Alice
	privAliceBytes, _ := base64.StdEncoding.DecodeString("fNOf3xWjFZYGYWixorM5+JR+u/2Udnc9Zw5+9rSvjqo=")
	privAlice, _ := x25519.PrivateKeyFromBytes(privAliceBytes)

	// 2) We resolve the DID Document for Bob
	dBob, _ := did.Parse("did:key:z6MkgRNXpJRbEE6FoXhT8KWHwJo4KyzFo1FdSEFpRLh5vuXZ")
	docBob, _ := dBob.Document()

	// 3) We perform the key agreement
	key, method, _ := did.FindMatchingKeyAgreement(docBob.KeyAgreement(), privAlice)

	fmt.Println("Shared key:", base64.StdEncoding.EncodeToString(key))
	fmt.Println("Verification method used:", method.Type(), method.ID())

	// Output: Shared key: 7G1qwS/gn5W1hxBtObHc3F0jA7m2vuXkLJJ32yBuHVQ=
	// Verification method used: X25519KeyAgreementKey2020 did:key:z6MkgRNXpJRbEE6FoXhT8KWHwJo4KyzFo1FdSEFpRLh5vuXZ#z6LSjeQx2VkXz8yirhrYJv8uicu9BBaeYU3Q1D9sFBovhmPF
}
```

## Features

### Supported DID Methods

| Method    | Controller | Verifier | Description                                        |
|-----------|------------|----------|----------------------------------------------------|
| `did:key` | ✅          | ✅        | Self-contained DIDs based on public keys           |
| `did:plc` | ❌          | ✅        | Bluesky's DID with rotation and a public directory |

### Supported Verification Method Types

| Type                                | Use Case                 |
|-------------------------------------|--------------------------|
| `EcdsaSecp256k1VerificationKey2019` | secp256k1 signatures     |
| `Ed25519VerificationKey2018`        | Ed25519 signatures       |
| `Ed25519VerificationKey2020`        | Ed25519 signatures       |
| `JsonWebKey2020`                    | All supported algorithms |
| `Multikey`                          | All supported algorithms |
| `P256Key2021`                       | P-256 signatures         |
| `X25519KeyAgreementKey2020`         | X25519 key agreement     |

### Supported Cryptographic Algorithms

#### Signing Keys
| Algorithm       | Signature Format  | Public Key Formats                  | Private Key Formats       |
|-----------------|-------------------|-------------------------------------|---------------------------|
| Ed25519         | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM |
| ECDSA P-256     | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM |
| ECDSA P-384     | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM |
| ECDSA P-521     | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM |
| ECDSA secp256k1 | Raw bytes, ASN.1  | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM |
| RSA             | PKCS#1 v1.5 ASN.1 | X.509 DER/PEM, Multibase            | PKCS#8 DER/PEM            |


#### Key Agreement (Encryption)
| Algorithm | Public Key Formats                  | Private Key Formats       |
|-----------|-------------------------------------|---------------------------|
| X25519    | Raw bytes, X.509 DER/PEM, Multibase | Raw bytes, PKCS#8 DER/PEM |

