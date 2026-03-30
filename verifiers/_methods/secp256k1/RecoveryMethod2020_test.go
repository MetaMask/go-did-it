package secp256k1vm_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	secp256k1crypto "github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/MetaMask/go-did-it/didtest"
	secp256k1vm "github.com/MetaMask/go-did-it/verifiers/_methods/secp256k1"
)

// Test key material from:
// https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020/blob/master/docs/unlockedDID.json

func privKeyFromHex(t *testing.T, h string) *secp256k1crypto.PrivateKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	require.NoError(t, err)
	k, err := secp256k1crypto.PrivateKeyFromBytes(b)
	require.NoError(t, err)
	return k
}

// TestRecoveryMethod2020_EthereumAddressDerivation verifies that our Keccak-256 address
// derivation matches the known address for a known private key from the DIF test vectors.
func TestRecoveryMethod2020_EthereumAddressDerivation(t *testing.T) {
	// vm-3: privateKeyHex -> known ethereumAddress
	priv := privKeyFromHex(t, "278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f")
	message := []byte("test message")
	sig := priv.SignToCompact(message, crypto.WithSigningHash(crypto.KECCAK_256))

	vm := secp256k1vm.NewRecoveryMethod2020FromEthereumAddress(
		"did:example:123#vm-3",
		"0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74",
		didtest.PersonaAlice.DID(),
	)
	ok, err := vm.VerifyBytes(message, sig)
	require.NoError(t, err)
	require.True(t, ok, "address derivation from known private key must match the known address")
}

// TestRecoveryMethod2020_BlockchainAccountIdDerivation verifies that our address derivation
// matches the known blockchainAccountId for a known private key from the DIF test vectors.
func TestRecoveryMethod2020_BlockchainAccountIdDerivation(t *testing.T) {
	// vm-4: privateKeyHex -> known blockchainAccountId
	priv := privKeyFromHex(t, "0b622f72d0cb4f6d7eebfb9d97375aec891c9836fcf813310069cfffdc7811d6")
	message := []byte("test message")
	sig := priv.SignToCompact(message, crypto.WithSigningHash(crypto.KECCAK_256))

	vm := secp256k1vm.NewRecoveryMethod2020FromBlockchainAccountId(
		"did:example:123#vm-4",
		"eip155:1:0xa136D6b820E41858b57b0136514e75f4174ceA5f",
		didtest.PersonaAlice.DID(),
	)
	ok, err := vm.VerifyBytes(message, sig)
	require.NoError(t, err)
	require.True(t, ok, "address derivation from known private key must match the known blockchainAccountId")
}

func TestRecoveryMethod2020_JsonRoundTrip_JWK(t *testing.T) {
	data := `{
		"id": "did:example:123#vm-1",
		"type": "EcdsaSecp256k1RecoveryMethod2020",
		"controller": "did:example:123",
		"publicKeyJwk": {
			"crv": "secp256k1",
			"kid": "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
			"kty": "EC",
			"x": "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
			"y": "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
		}
	}`

	var vm secp256k1vm.RecoveryMethod2020
	require.NoError(t, json.Unmarshal([]byte(data), &vm))

	out, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(out))
}

func TestRecoveryMethod2020_JsonRoundTrip_Hex(t *testing.T) {
	data := `{
		"id": "did:example:123#vm-2",
		"type": "EcdsaSecp256k1RecoveryMethod2020",
		"controller": "did:example:123",
		"publicKeyHex": "027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770"
	}`

	var vm secp256k1vm.RecoveryMethod2020
	require.NoError(t, json.Unmarshal([]byte(data), &vm))

	out, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(out))
}

func TestRecoveryMethod2020_JsonRoundTrip_EthereumAddress(t *testing.T) {
	data := `{
		"id": "did:example:123#vm-3",
		"type": "EcdsaSecp256k1RecoveryMethod2020",
		"controller": "did:example:123",
		"ethereumAddress": "0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74"
	}`

	var vm secp256k1vm.RecoveryMethod2020
	require.NoError(t, json.Unmarshal([]byte(data), &vm))

	out, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(out))
}

func TestRecoveryMethod2020_JsonRoundTrip_BlockchainAccountId(t *testing.T) {
	data := `{
		"id": "did:example:123#vm-4",
		"type": "EcdsaSecp256k1RecoveryMethod2020",
		"controller": "did:example:123",
		"blockchainAccountId": "eip155:1:0xa136D6b820E41858b57b0136514e75f4174ceA5f"
	}`

	var vm secp256k1vm.RecoveryMethod2020
	require.NoError(t, json.Unmarshal([]byte(data), &vm))

	out, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(out))
}

// publicKeyJwk and publicKeyHex default to SHA-256 (ES256K-R spec).
func TestRecoveryMethod2020_VerifyBytes_PublicKeyHex_DefaultHash(t *testing.T) {
	priv := privKeyFromHex(t, "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c")
	message := []byte("test message")

	vm := secp256k1vm.NewRecoveryMethod2020FromHex(
		"did:example:123#vm-2",
		priv.Public().(*secp256k1crypto.PublicKey),
		didtest.PersonaAlice.DID(),
	)

	// default hash (SHA-256) on both sides
	sig := priv.SignToCompact(message)
	ok, err := vm.VerifyBytes(message, sig)
	require.NoError(t, err)
	require.True(t, ok)

	// explicit SHA-256 override produces same result
	sigExplicit := priv.SignToCompact(message, crypto.WithSigningHash(crypto.SHA256))
	ok, err = vm.VerifyBytes(message, sigExplicit, crypto.WithSigningHash(crypto.SHA256))
	require.NoError(t, err)
	require.True(t, ok)

	// Keccak-256 signed against SHA-256 verifier must fail
	sigKeccak := priv.SignToCompact(message, crypto.WithSigningHash(crypto.KECCAK_256))
	ok, err = vm.VerifyBytes(message, sigKeccak)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRecoveryMethod2020_VerifyBytes_PublicKeyJWK_DefaultHash(t *testing.T) {
	priv := privKeyFromHex(t, "ae1605b013c5f6adfeb994e1cbb0777382c317ff309e8cc5500126e4b2c2e19c")
	message := []byte("test message")

	vm := secp256k1vm.NewRecoveryMethod2020FromJWK(
		"did:example:123#vm-1",
		priv.Public().(*secp256k1crypto.PublicKey),
		didtest.PersonaAlice.DID(),
	)

	// default hash (SHA-256) on both sides
	sig := priv.SignToCompact(message)
	ok, err := vm.VerifyBytes(message, sig)
	require.NoError(t, err)
	require.True(t, ok)

	// Keccak-256 signed against SHA-256 verifier must fail
	sigKeccak := priv.SignToCompact(message, crypto.WithSigningHash(crypto.KECCAK_256))
	ok, err = vm.VerifyBytes(message, sigKeccak)
	require.NoError(t, err)
	require.False(t, ok)
}

// ethereumAddress and blockchainAccountId default to Keccak-256.
func TestRecoveryMethod2020_VerifyBytes_EthereumAddress_DefaultHash(t *testing.T) {
	priv := privKeyFromHex(t, "278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f")
	message := []byte("test message")

	vm := secp256k1vm.NewRecoveryMethod2020FromEthereumAddress(
		"did:example:123#vm-3",
		"0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74",
		didtest.PersonaAlice.DID(),
	)

	// default hash (Keccak-256) on both sides
	sig := priv.SignToCompact(message, crypto.WithSigningHash(crypto.KECCAK_256))
	ok, err := vm.VerifyBytes(message, sig)
	require.NoError(t, err)
	require.True(t, ok)

	// explicit Keccak-256 override produces same result
	ok, err = vm.VerifyBytes(message, sig, crypto.WithSigningHash(crypto.KECCAK_256))
	require.NoError(t, err)
	require.True(t, ok)

	// SHA-256 signed against Keccak-256 verifier must fail
	sigSHA256 := priv.SignToCompact(message)
	ok, err = vm.VerifyBytes(message, sigSHA256)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRecoveryMethod2020_VerifyBytes_BlockchainAccountId_DefaultHash(t *testing.T) {
	priv := privKeyFromHex(t, "0b622f72d0cb4f6d7eebfb9d97375aec891c9836fcf813310069cfffdc7811d6")
	message := []byte("test message")

	vm := secp256k1vm.NewRecoveryMethod2020FromBlockchainAccountId(
		"did:example:123#vm-4",
		"eip155:1:0xa136D6b820E41858b57b0136514e75f4174ceA5f",
		didtest.PersonaAlice.DID(),
	)

	// default hash (Keccak-256) on both sides
	sig := priv.SignToCompact(message, crypto.WithSigningHash(crypto.KECCAK_256))
	ok, err := vm.VerifyBytes(message, sig)
	require.NoError(t, err)
	require.True(t, ok)

	// SHA-256 signed against Keccak-256 verifier must fail
	sigSHA256 := priv.SignToCompact(message)
	ok, err = vm.VerifyBytes(message, sigSHA256)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRecoveryMethod2020_VerifyBytes_WrongKey(t *testing.T) {
	pub, _, err := secp256k1crypto.GenerateKeyPair()
	require.NoError(t, err)
	_, otherPriv, err := secp256k1crypto.GenerateKeyPair()
	require.NoError(t, err)

	vm := secp256k1vm.NewRecoveryMethod2020FromHex("did:example:123#vm-1", pub, didtest.PersonaAlice.DID())
	sig := otherPriv.SignToCompact([]byte("test message"))

	ok, err := vm.VerifyBytes([]byte("test message"), sig)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRecoveryMethod2020_VerifyBytes_BadSigLength(t *testing.T) {
	pub, _, err := secp256k1crypto.GenerateKeyPair()
	require.NoError(t, err)
	vm := secp256k1vm.NewRecoveryMethod2020FromHex("did:example:123#vm-1", pub, didtest.PersonaAlice.DID())

	_, err = vm.VerifyBytes([]byte("msg"), make([]byte, 64))
	require.Error(t, err)
}

func TestRecoveryMethod2020_VerifyASN1_Unsupported(t *testing.T) {
	pub, _, err := secp256k1crypto.GenerateKeyPair()
	require.NoError(t, err)
	vm := secp256k1vm.NewRecoveryMethod2020FromHex("did:example:123#vm-1", pub, didtest.PersonaAlice.DID())

	_, err = vm.VerifyASN1([]byte("msg"), []byte("sig"))
	require.Error(t, err)
}
