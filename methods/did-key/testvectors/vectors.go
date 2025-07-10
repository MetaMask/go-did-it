package testvectors

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/mr-tron/base58"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/ed25519"
	"github.com/INFURA/go-did/crypto/jwk"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/secp256k1"
	ed25519vm "github.com/INFURA/go-did/verifications/ed25519"
	"github.com/INFURA/go-did/verifications/jsonwebkey"
	p256vm "github.com/INFURA/go-did/verifications/p256"
	secp256k1vm "github.com/INFURA/go-did/verifications/secp256k1"
)

// Origin: https://github.com/w3c-ccg/did-key-spec/tree/main/test-vectors
// See also: https://github.com/w3c-ccg/did-key-spec/pull/73

//go:embed *.json
var testVectorFiles embed.FS

type Vector struct {
	DID      string
	Pub      crypto.PublicKey
	Priv     crypto.PrivateKey
	Document string

	// Those test vectors are done in a way that, for example, if the input is a JWK the expected verification method
	// is JsonWebKey2020. This field collects those hints so that the future resolution matches the expected document.
	ResolutionHint []string
}

func AllFiles() []string {
	files, err := testVectorFiles.ReadDir(".")
	if err != nil {
		panic(err)
	}
	var res []string
	for _, f := range files {
		// filter some
		switch {
		case strings.HasPrefix(f.Name(), "bls"): // BLS is not supported
		case strings.HasPrefix(f.Name(), "x25519"): // this file has a complete different structure
		default:
			res = append(res, f.Name())
		}
	}
	return res
}

func LoadTestVectors(filename string) ([]Vector, error) {
	data, err := testVectorFiles.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var res []Vector

	var vectorsData map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &vectorsData); err != nil {
		return nil, err
	}

	for k, v := range vectorsData {
		vect := Vector{DID: k}
		vect.Document = string(v["didDocument"])

		// naked JWK
		if v["publicKeyJwk"] != nil {
			var pub jwk.PublicJwk
			if err = json.Unmarshal(v["publicKeyJwk"], &pub); err != nil {
				return nil, err
			}
			vect.Pub = pub.Pubkey
			var priv jwk.PrivateJwk
			if err = json.Unmarshal(v["privateKeyJwk"], &priv); err != nil {
				return nil, err
			}
			vect.Priv = priv.Privkey
			vect.ResolutionHint = append(vect.ResolutionHint, jsonwebkey.Type)
		}

		if v["verificationMethod"] != nil {
			var vm map[string]json.RawMessage
			if err = json.Unmarshal(v["verificationMethod"], &vm); err != nil {
				return nil, err
			}

			var vmType string
			if err = json.Unmarshal(vm["type"], &vmType); err != nil {
				return nil, err
			}
			vect.ResolutionHint = append(vect.ResolutionHint, vmType)

			if vm["publicKeyJwk"] != nil {
				var pub jwk.PublicJwk
				if err = json.Unmarshal(vm["publicKeyJwk"], &pub); err != nil {
					return nil, err
				}
				vect.Pub = pub.Pubkey
				var priv jwk.PrivateJwk
				if err = json.Unmarshal(vm["privateKeyJwk"], &priv); err != nil {
					return nil, err
				}
				vect.Priv = priv.Privkey
			}

			var pubBytes []byte
			if vm["publicKeyBase58"] != nil {
				var pubB58 string
				if err = json.Unmarshal(vm["publicKeyBase58"], &pubB58); err != nil {
					return nil, err
				}
				pubBytes, err = base58.DecodeAlphabet(pubB58, base58.BTCAlphabet)
				if err != nil {
					return nil, err
				}
			}
			var privBytes []byte
			if vm["privateKeyBase58"] != nil {
				var privB58 string
				if err = json.Unmarshal(vm["privateKeyBase58"], &privB58); err != nil {
					return nil, err
				}
				privBytes, err = base58.DecodeAlphabet(privB58, base58.BTCAlphabet)
				if err != nil {
					return nil, err
				}
			}

			switch vmType {
			case p256vm.Type2021:
				vect.Pub, err = p256.PublicKeyFromBytes(pubBytes)
				if err != nil {
					return nil, err
				}
				vect.Priv, err = p256.PrivateKeyFromBytes(privBytes)
				if err != nil {
					return nil, err
				}
			}
		}

		if v["verificationKeyPair"] != nil {
			var vkp map[string]json.RawMessage
			if err = json.Unmarshal(v["verificationKeyPair"], &vkp); err != nil {
				return nil, err
			}

			var vmType string
			if err = json.Unmarshal(vkp["type"], &vmType); err != nil {
				return nil, err
			}
			vect.ResolutionHint = append(vect.ResolutionHint, vmType)

			var pubBytes []byte
			if vkp["publicKeyBase58"] != nil {
				var pubB58 string
				if err = json.Unmarshal(vkp["publicKeyBase58"], &pubB58); err != nil {
					return nil, err
				}
				pubBytes, err = base58.DecodeAlphabet(pubB58, base58.BTCAlphabet)
				if err != nil {
					return nil, err
				}
			}
			var privBytes []byte
			if vkp["privateKeyBase58"] != nil {
				var privB58 string
				if err = json.Unmarshal(vkp["privateKeyBase58"], &privB58); err != nil {
					return nil, err
				}
				privBytes, err = base58.DecodeAlphabet(privB58, base58.BTCAlphabet)
				if err != nil {
					return nil, err
				}
			}

			switch vmType {
			case secp256k1vm.Type2019:
				vect.Pub, err = secp256k1.PublicKeyFromBytes(pubBytes)
				if err != nil {
					return nil, err
				}
				vect.Priv, err = secp256k1.PrivateKeyFromBytes(privBytes)
				if err != nil {
					return nil, err
				}
			case ed25519vm.Type2018:
				vect.Pub, err = ed25519.PublicKeyFromBytes(pubBytes)
				if err != nil {
					return nil, err
				}
				seed, err := hex.DecodeString(strings.Trim(string(v["seed"]), "\""))
				if err != nil {
					return nil, err
				}
				vect.Priv, err = ed25519.PrivateKeyFromSeed(seed)
				if err != nil {
					return nil, err
				}
			case jsonwebkey.Type:
				var pub jwk.PublicJwk
				if err = json.Unmarshal(vkp["publicKeyJwk"], &pub); err != nil {
					return nil, err
				}
				vect.Pub = pub.Pubkey
				var priv jwk.PrivateJwk
				if err = json.Unmarshal(vkp["privateKeyJwk"], &priv); err != nil {
					return nil, err
				}
				vect.Priv = priv.Privkey
				vect.ResolutionHint = append(vect.ResolutionHint, jsonwebkey.Type)
			}
		}

		if v["keyAgreementKeyPair"] != nil {
			var kakp map[string]json.RawMessage
			if err = json.Unmarshal(v["keyAgreementKeyPair"], &kakp); err != nil {
				return nil, err
			}

			var vmType string
			if err = json.Unmarshal(kakp["type"], &vmType); err != nil {
				return nil, err
			}
			vect.ResolutionHint = append(vect.ResolutionHint, vmType)
		}

		res = append(res, vect)
	}

	return res, nil
}
