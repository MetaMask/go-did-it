package did

import (
	"fmt"

	"github.com/MetaMask/go-did-it/crypto"
)

// TryAllVerifyBytes tries to verify the signature as bytes with all the methods in the slice.
// It returns true if the signature is verified, and the method that verified it.
// If no method verifies the signature, it returns false and nil.
func TryAllVerifyBytes(methods []VerificationMethodSignature, data []byte, sig []byte, opts ...crypto.SigningOption) (bool, VerificationMethodSignature) {
	for _, method := range methods {
		if valid, err := method.VerifyBytes(data, sig, opts...); err == nil && valid {
			return true, method
		}
	}
	return false, nil
}

// TryAllVerifyASN1 tries to verify the signature as ASN.1 with all the methods in the slice.
// It returns true if the signature is verified, and the method that verified it.
// If no method verifies the signature, it returns false and nil.
func TryAllVerifyASN1(methods []VerificationMethodSignature, data []byte, sig []byte, opts ...crypto.SigningOption) (bool, VerificationMethodSignature) {
	for _, method := range methods {
		if valid, err := method.VerifyASN1(data, sig, opts...); err == nil && valid {
			return true, method
		}
	}
	return false, nil
}

// FindMatchingKeyAgreement tries to find a matching key agreement method for the given private key type.
// It returns the shared key as well as the selected method.
// If no matching method is found, it returns an error.
func FindMatchingKeyAgreement(methods []VerificationMethodKeyAgreement, priv crypto.PrivateKeyKeyExchange) ([]byte, VerificationMethodKeyAgreement, error) {
	for _, method := range methods {
		if method.PrivateKeyIsCompatible(priv) {
			key, err := method.KeyExchange(priv)
			return key, method, err
		}
	}
	return nil, nil, fmt.Errorf("no matching key agreement found")
}
