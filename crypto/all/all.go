// Package all registers every key algorithm supported by this module into the crypto.DefaultKeySet KeySet.
//
// Import it for its side effect when you want the global default to accept everything, typically in
// tests or kitchen-sink tools:
//
//	import _ "github.com/MetaMask/go-did-it/crypto/all"
//
// It pulls in every algorithm package, so only this package pays that binary-size cost. For finer
// control, register a subset yourself with crypto.Register(ed25519.KeyType(), ...) or build an explicit
// crypto.KeySet.
package all

import (
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/p384"
	"github.com/MetaMask/go-did-it/crypto/p521"
	"github.com/MetaMask/go-did-it/crypto/rsa"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/MetaMask/go-did-it/crypto/x25519"
)

func init() {
	crypto.Register(
		ed25519.KeyType(),
		p256.KeyType(),
		p384.KeyType(),
		p521.KeyType(),
		secp256k1.KeyType(),
		x25519.KeyType(),
		rsa.KeyType(), // any size within RSA's supported range
	)
}
