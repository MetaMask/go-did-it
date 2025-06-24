package did

import (
	"fmt"

	"github.com/INFURA/go-did/crypto"
)

// TryAllVerify tries to verify the signature with all the methods in the slice.
// It returns true if the signature is verified, and the method that verified it.
// If no method verifies the signature, it returns false and nil.
func TryAllVerify(methods []VerificationMethodSignature, data []byte, sig []byte) (bool, VerificationMethodSignature) {
	for _, method := range methods {
		if method.Verify(data, sig) {
			return true, method
		}
	}
	return false, nil
}

// FindMatchingKeyAgreement tries to find a matching key agreement method for the given private key type.
// It returns the shared key as well as the selected method.
// If no matching method is found, it returns an error.
func FindMatchingKeyAgreement(methods []VerificationMethodKeyAgreement, priv crypto.KeyExchangePrivateKey) ([]byte, VerificationMethodKeyAgreement, error) {
	for _, method := range methods {
		if method.PrivateKeyIsCompatible(priv) {
			key, err := method.KeyExchange(priv)
			return key, method, err
		}
	}
	return nil, nil, fmt.Errorf("no matching key agreement found")
}
