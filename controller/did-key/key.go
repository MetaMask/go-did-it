package didkeyctl

import (
	"github.com/MetaMask/go-did-it/crypto"
	didkey "github.com/MetaMask/go-did-it/verifiers/did-key"
)

// FromPublicKey builds the did:key DID that encodes pub.
func FromPublicKey(pub crypto.PublicKey) didkey.DidKey {
	return didkey.FromPublicKey(pub)
}

// FromPrivateKey builds the did:key DID that encodes priv's public key.
func FromPrivateKey(priv crypto.PrivateKey) didkey.DidKey {
	return didkey.FromPrivateKey(priv)
}
