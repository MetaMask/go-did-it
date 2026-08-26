// Package all registers every verification method type supported by this module, so that
// arbitrary DID documents (e.g. resolved through did:web) can be decoded.
//
// Import it for its side effect when you want document parsing to understand every
// verification method type, typically in tests or kitchen-sink tools:
//
//	import _ "github.com/MetaMask/go-did-it/verifiers/_methods/all"
//
// It pulls in every verification method package (and their key algorithm packages), so only
// this package pays that binary-size cost. For finer control, import only the verification
// method packages you expect. Note that decoding a key additionally requires its algorithm
// in the used crypto.KeySet (see crypto/all).
package all

import (
	_ "github.com/MetaMask/go-did-it/verifiers/_methods/ed25519"
	_ "github.com/MetaMask/go-did-it/verifiers/_methods/jsonwebkey"
	_ "github.com/MetaMask/go-did-it/verifiers/_methods/multikey"
	_ "github.com/MetaMask/go-did-it/verifiers/_methods/p256"
	_ "github.com/MetaMask/go-did-it/verifiers/_methods/secp256k1"
	_ "github.com/MetaMask/go-did-it/verifiers/_methods/x25519"
)
