package did

import (
	"encoding/json"
	"fmt"
)

// Specification: https://www.w3.org/TR/cid-1.0/#services
// List of service types and their fields: https://www.w3.org/TR/did-extensions-properties/#service-types

// Services is a collection of Service.
type Services []Service

// ServiceById retrieves a Service from the Services slice by its id.
// Returns the Service and true if found, otherwise returns an empty Service and false.
func (ss Services) ServiceById(id string) (Service, bool) {
	for _, s := range ss {
		if s.Id == id {
			return s, true
		}
	}
	return Service{}, false
}

// ServiceByType returns zero or one Service matching the given type.
// If there is more than one service for that type, the first match is returned.
func (ss Services) ServiceByType(_type string) (Service, bool) {
	for _, s := range ss {
		if s.HasType(_type) {
			return s, true
		}
	}
	return Service{}, false
}

// Service is a means of communicating or interacting with the DID subject or associated entities
// via one or more service endpoints.
// It can have one or more types.
type Service struct {
	Id        string
	Types     []string
	Endpoints []any // either strEndpoint or mapEndpoint
}

func (s Service) HasType(_type string) bool {
	for _, t := range s.Types {
		if t == _type {
			return true
		}
	}
	return false
}

func (s Service) MarshalJSON() ([]byte, error) {
	var aux struct {
		Id       string `json:"id"`
		Type     any    `json:"type"`
		Endpoint any    `json:"serviceEndpoint"`
	}

	aux.Id = s.Id

	switch len(s.Types) {
	case 0:
		return nil, fmt.Errorf("service type is required")
	case 1:
		aux.Type = s.Types[0]
	default:
		aux.Type = s.Types
	}

	switch len(s.Endpoints) {
	case 0:
		return nil, fmt.Errorf("service endpoint is required")
	case 1:
		aux.Endpoint = s.Endpoints[0]
	default:
		aux.Endpoint = s.Endpoints
	}

	return json.Marshal(aux)
}

func (s *Service) UnmarshalJSON(bytes []byte) error {
	var aux struct {
		Id       string          `json:"id"`
		Type     json.RawMessage `json:"type"`
		Endpoint json.RawMessage `json:"serviceEndpoint"`
	}

	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}

	if len(aux.Id) == 0 {
		return fmt.Errorf("service id is required")
	}
	s.Id = aux.Id

	s.Types, err = unmarshalSingleOrArray[string](aux.Type)
	if err != nil {
		return err
	}
	if len(s.Types) == 0 {
		return fmt.Errorf("service type is required")
	}
	for _, _type := range s.Types {
		if len(_type) == 0 {
			return fmt.Errorf("invalid service type: must not be empty string")
		}
	}

	s.Endpoints, err = unmarshalSingleOrArray[any](aux.Endpoint)
	if err != nil {
		return err
	}
	if len(s.Endpoints) == 0 {
		return fmt.Errorf("service endpoint is required")
	}
	for i, endpoint := range s.Endpoints {
		switch endpoint := endpoint.(type) {
		case string:
			s.Endpoints[i] = StrEndpoint(endpoint)
		case map[string]any:
			s.Endpoints[i] = MapEndpoint(endpoint)
		default:
			return fmt.Errorf("endpoint must be %T or %T", StrEndpoint(""), MapEndpoint{})
		}
	}

	return nil
}

type StrEndpoint string

type MapEndpoint map[string]any

func unmarshalSingleOrArray[T any](data json.RawMessage) ([]T, error) {
	if data == nil {
		return nil, nil
	}

	var single T
	if err := json.Unmarshal(data, &single); err == nil {
		return []T{single}, nil
	}

	var array []T
	if err := json.Unmarshal(data, &array); err == nil {
		return array, nil
	}

	return nil, fmt.Errorf("must be %T or array of %T", single, single)
}
