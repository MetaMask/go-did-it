package jwk

import "encoding/json"

// Specification:
// - https://www.rfc-editor.org/rfc/rfc7517#section-5 (JWK Set)

// PublicJwks is a JWK Set holding public keys
type PublicJwks struct {
	Keys []PublicJwk
}

func (s PublicJwks) MarshalJSON() ([]byte, error) {
	keys := s.Keys
	if keys == nil {
		keys = []PublicJwk{}
	}
	return json.Marshal(struct {
		Keys []PublicJwk `json:"keys"`
	}{Keys: keys})
}

func (s *PublicJwks) UnmarshalJSON(data []byte) error {
	var aux struct {
		Keys []PublicJwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.Keys = aux.Keys
	return nil
}

// PrivateJwks is a JWK Set holding private keys
type PrivateJwks struct {
	Keys []PrivateJwk
}

func (s PrivateJwks) MarshalJSON() ([]byte, error) {
	keys := s.Keys
	if keys == nil {
		keys = []PrivateJwk{}
	}
	return json.Marshal(struct {
		Keys []PrivateJwk `json:"keys"`
	}{Keys: keys})
}

func (s *PrivateJwks) UnmarshalJSON(data []byte) error {
	var aux struct {
		Keys []PrivateJwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.Keys = aux.Keys
	return nil
}
