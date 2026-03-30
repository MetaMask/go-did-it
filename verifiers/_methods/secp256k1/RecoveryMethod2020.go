package secp256k1vm

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/jwk"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
)

// Specification: https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/

const (
	JsonLdContext2020 = "https://w3id.org/security/suites/secp256k1recovery-2020/v2"
	TypeRecovery2020  = "EcdsaSecp256k1RecoveryMethod2020"
)

var _ did.VerificationMethodSignature = &RecoveryMethod2020{}

// RecoveryMethod2020 implements EcdsaSecp256k1RecoveryMethod2020.
// Exactly one key material field is set: publicKeyJwk, publicKeyHex, ethereumAddress,
// or blockchainAccountId. Verification recovers the public key from the 65-byte compact
// signature and checks it against the stored key material.
type RecoveryMethod2020 struct {
	id         string
	controller string

	// exactly one of these is set
	pubKeyJwk        *jwk.PublicJwk       // publicKeyJwk
	pubKeyHex        *secp256k1.PublicKey // publicKeyHex
	ethAddress       string               // ethereumAddress
	blockchainAcctId string               // blockchainAccountId
}

func NewRecoveryMethod2020FromJWK(id string, pubkey *secp256k1.PublicKey, controller did.DID) *RecoveryMethod2020 {
	return &RecoveryMethod2020{
		id:         id,
		controller: controller.String(),
		pubKeyJwk:  &jwk.PublicJwk{Pubkey: pubkey},
	}
}

func NewRecoveryMethod2020FromHex(id string, pubkey *secp256k1.PublicKey, controller did.DID) *RecoveryMethod2020 {
	return &RecoveryMethod2020{
		id:         id,
		controller: controller.String(),
		pubKeyHex:  pubkey,
	}
}

func NewRecoveryMethod2020FromEthereumAddress(id string, address string, controller did.DID) *RecoveryMethod2020 {
	return &RecoveryMethod2020{
		id:         id,
		controller: controller.String(),
		ethAddress: address,
	}
}

func NewRecoveryMethod2020FromBlockchainAccountId(id string, blockchainAccountId string, controller did.DID) *RecoveryMethod2020 {
	return &RecoveryMethod2020{
		id:               id,
		controller:       controller.String(),
		blockchainAcctId: blockchainAccountId,
	}
}

func (vm RecoveryMethod2020) MarshalJSON() ([]byte, error) {
	out := struct {
		ID                  string         `json:"id"`
		Type                string         `json:"type"`
		Controller          string         `json:"controller"`
		PublicKeyJwk        *jwk.PublicJwk `json:"publicKeyJwk,omitempty"`
		PublicKeyHex        string         `json:"publicKeyHex,omitempty"`
		EthereumAddress     string         `json:"ethereumAddress,omitempty"`
		BlockchainAccountId string         `json:"blockchainAccountId,omitempty"`
	}{
		ID:         vm.ID(),
		Type:       vm.Type(),
		Controller: vm.Controller(),
	}
	switch {
	case vm.pubKeyJwk != nil:
		out.PublicKeyJwk = vm.pubKeyJwk
	case vm.pubKeyHex != nil:
		out.PublicKeyHex = hex.EncodeToString(vm.pubKeyHex.ToBytes())
	case vm.ethAddress != "":
		out.EthereumAddress = vm.ethAddress
	case vm.blockchainAcctId != "":
		out.BlockchainAccountId = vm.blockchainAcctId
	}
	return json.Marshal(out)
}

func (vm *RecoveryMethod2020) UnmarshalJSON(data []byte) error {
	aux := struct {
		ID                  string         `json:"id"`
		Type                string         `json:"type"`
		Controller          string         `json:"controller"`
		PublicKeyJwk        *jwk.PublicJwk `json:"publicKeyJwk,omitempty"`
		PublicKeyHex        string         `json:"publicKeyHex,omitempty"`
		EthereumAddress     string         `json:"ethereumAddress,omitempty"`
		BlockchainAccountId string         `json:"blockchainAccountId,omitempty"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Type != vm.Type() {
		return errors.New("invalid type")
	}
	vm.id = aux.ID
	if len(vm.id) == 0 {
		return errors.New("invalid id")
	}
	vm.controller = aux.Controller
	if !did.HasValidDIDSyntax(vm.controller) {
		return errors.New("invalid controller")
	}

	count := 0
	if aux.PublicKeyJwk != nil {
		count++
	}
	if aux.PublicKeyHex != "" {
		count++
	}
	if aux.EthereumAddress != "" {
		count++
	}
	if aux.BlockchainAccountId != "" {
		count++
	}
	if count != 1 {
		return fmt.Errorf("exactly one key material field must be present, got %d", count)
	}

	// reset in case of unmarshalling into an existing struct
	vm.pubKeyJwk = nil
	vm.pubKeyHex = nil
	vm.ethAddress = ""
	vm.blockchainAcctId = ""
	switch {
	case aux.PublicKeyJwk != nil:
		if _, ok := aux.PublicKeyJwk.Pubkey.(*secp256k1.PublicKey); !ok {
			return errors.New("publicKeyJwk must contain a secp256k1 key")
		}
		vm.pubKeyJwk = aux.PublicKeyJwk
	case aux.PublicKeyHex != "":
		b, err := hex.DecodeString(aux.PublicKeyHex)
		if err != nil {
			return fmt.Errorf("invalid publicKeyHex: %w", err)
		}
		pubkey, err := secp256k1.PublicKeyFromBytes(b)
		if err != nil {
			return fmt.Errorf("invalid publicKeyHex: %w", err)
		}
		vm.pubKeyHex = pubkey
	case aux.EthereumAddress != "":
		vm.ethAddress = aux.EthereumAddress
	case aux.BlockchainAccountId != "":
		vm.blockchainAcctId = aux.BlockchainAccountId
	}

	return nil
}

func (vm RecoveryMethod2020) ID() string {
	return vm.id
}

func (vm RecoveryMethod2020) Type() string {
	return TypeRecovery2020
}

func (vm RecoveryMethod2020) Controller() string {
	return vm.controller
}

func (vm RecoveryMethod2020) JsonLdContext() string {
	return JsonLdContext2020
}

// VerifyBytes verifies a secp256k1 ECDSA signature using public key recovery.
// The signature must be 65 bytes: [recovery_flag (1 byte) | R (32 bytes) | S (32 bytes)].
// The public key is recovered from the signature and compared against the stored key material.
//
// The default hash algorithm depends on the key material:
//   - publicKeyJwk / publicKeyHex: SHA-256 (per the ES256K-R spec)
//   - ethereumAddress / blockchainAccountId: Keccak-256 (Ethereum wallets sign with Keccak-256)
func (vm RecoveryMethod2020) VerifyBytes(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	if len(sig) != 65 {
		return false, fmt.Errorf("EcdsaSecp256k1RecoveryMethod2020: expected 65-byte compact signature, got %d bytes", len(sig))
	}

	defaultHash := vm.defaultHash()
	params := crypto.CollectSigningOptions(opts)
	hasher := params.HashOrDefault(defaultHash).New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	recovered, err := secp256k1.PublicKeyFromRecovery(sig, hash)
	if err != nil {
		// invalid signature
		return false, nil
	}

	switch {
	case vm.pubKeyJwk != nil:
		stored, ok := vm.pubKeyJwk.Pubkey.(*secp256k1.PublicKey)
		if !ok {
			return false, errors.New("publicKeyJwk is not a secp256k1 key")
		}
		return recovered.Equal(stored), nil
	case vm.pubKeyHex != nil:
		return recovered.Equal(vm.pubKeyHex), nil
	case vm.ethAddress != "":
		return strings.EqualFold(ethAddressFromPublicKey(recovered), vm.ethAddress), nil
	case vm.blockchainAcctId != "":
		return addressMatchesBlockchainAccountId(ethAddressFromPublicKey(recovered), vm.blockchainAcctId), nil
	default:
		return false, errors.New("no key material")
	}
}

// defaultHash returns the default hash algorithm for this key material.
// Ethereum-based formats use Keccak-256; spec-based formats use SHA-256.
func (vm RecoveryMethod2020) defaultHash() crypto.Hash {
	if vm.ethAddress != "" || vm.blockchainAcctId != "" {
		return crypto.KECCAK_256
	}
	return crypto.SHA256
}

// VerifyASN1 is not supported: ASN.1 DER signatures do not include a recovery flag.
// Use VerifyBytes with a 65-byte compact signature instead.
func (vm RecoveryMethod2020) VerifyASN1(_ []byte, _ []byte, _ ...crypto.SigningOption) (bool, error) {
	return false, errors.New("EcdsaSecp256k1RecoveryMethod2020 does not support ASN.1 signatures; use VerifyBytes with a 65-byte compact signature")
}

// ethAddressFromPublicKey derives the Ethereum address from a secp256k1 public key.
// It is the last 20 bytes of the Keccak-256 hash of the uncompressed key coordinates (X || Y).
func ethAddressFromPublicKey(pubkey *secp256k1.PublicKey) string {
	hasher := crypto.KECCAK_256.New()
	hasher.Write(pubkey.XBytes())
	hasher.Write(pubkey.YBytes())
	hash := hasher.Sum(nil)
	return "0x" + hex.EncodeToString(hash[12:])
}

// addressMatchesBlockchainAccountId extracts the address part from a CAIP-10 blockchainAccountId
// (e.g. "eip155:1:0x...") and compares it case-insensitively with addr.
func addressMatchesBlockchainAccountId(addr, blockchainAccountId string) bool {
	parts := strings.Split(blockchainAccountId, ":")
	return strings.EqualFold(addr, parts[len(parts)-1])
}
