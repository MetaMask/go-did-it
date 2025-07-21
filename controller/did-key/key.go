package didkeyctl

import (
	"github.com/ucan-wg/go-did-it"
	"github.com/ucan-wg/go-did-it/crypto"
	didkey "github.com/ucan-wg/go-did-it/verifiers/did-key"
)

func FromPublicKey(pub crypto.PublicKey) did.DID {
	return didkey.FromPublicKey(pub)
}

func FromPrivateKey(priv crypto.PrivateKey) did.DID {
	return didkey.FromPrivateKey(priv)
}
