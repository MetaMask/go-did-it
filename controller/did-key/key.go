package didkeyctl

import (
	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	didkey "github.com/MetaMask/go-did-it/verifiers/did-key"
)

func FromPublicKey(pub crypto.PublicKey) did.DID {
	return didkey.FromPublicKey(pub)
}

func FromPrivateKey(priv crypto.PrivateKey) did.DID {
	return didkey.FromPrivateKey(priv)
}
