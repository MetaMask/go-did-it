// Package dagcbor provides a minimal DAG-CBOR encoder for did:plc operations.
//
// DAG-CBOR (https://ipld.io/specs/codecs/dag-cbor/spec/) is a deterministic
// subset of CBOR (RFC 8949) used by the did:plc protocol to encode operations
// before signing and hashing.
//
// This encoder supports only the value types present in did:plc operations:
// null, strings, string arrays, string maps, nested any-value maps, and CID links.
// Map keys are sorted by the canonical DAG-CBOR ordering (shorter CBOR-encoded
// key first, ties broken lexicographically).
package dagcbor

import (
	"fmt"
	"sort"

	cid "github.com/ipfs/go-cid"
)

// Encode serializes v to DAG-CBOR bytes.
//
// Supported Go types:
//
//   - nil                → CBOR null (0xf6)
//   - string             → CBOR text string
//   - []string           → CBOR array of text strings
//   - map[string]string  → CBOR map with canonical key ordering
//   - map[string]any     → CBOR map; values may be any supported type
//   - cid.Cid            → CBOR tag 42 byte-string (CID link)
func Encode(v any) ([]byte, error) {
	return appendValue(make([]byte, 0, 256), v)
}

func appendValue(buf []byte, v any) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return append(buf, 0xf6), nil

	case string:
		return appendString(buf, v), nil

	case []string:
		buf = appendHead(buf, majorArray, uint64(len(v)))
		for _, s := range v {
			buf = appendString(buf, s)
		}
		return buf, nil

	case map[string]string:
		keys := sortedKeys(v)
		buf = appendHead(buf, majorMap, uint64(len(keys)))
		for _, k := range keys {
			buf = appendString(buf, k)
			buf = appendString(buf, v[k])
		}
		return buf, nil

	case map[string]any:
		keys := sortedKeys(v)
		buf = appendHead(buf, majorMap, uint64(len(keys)))
		var err error
		for _, k := range keys {
			buf = appendString(buf, k)
			if buf, err = appendValue(buf, v[k]); err != nil {
				return nil, err
			}
		}
		return buf, nil

	case cid.Cid:
		// CBOR tag 42, followed by a byte-string prefixed with 0x00 (the "identity" multibase byte
		// required by the DAG-CBOR spec to distinguish CID links from raw bytes).
		buf = append(buf, 0xd8, 0x2a) // tag(42)
		raw := v.Bytes()
		cidWithPrefix := make([]byte, 1+len(raw))
		cidWithPrefix[0] = 0x00
		copy(cidWithPrefix[1:], raw)
		return appendBytes(buf, cidWithPrefix), nil

	default:
		return nil, fmt.Errorf("dagcbor: unsupported type %T", v)
	}
}

const (
	majorBytes  byte = 2
	majorString byte = 3
	majorArray  byte = 4
	majorMap    byte = 5
)

// appendHead encodes a CBOR head: the major type (upper 3 bits) combined with
// the additional info / argument (lower 5 bits or following bytes).
func appendHead(buf []byte, major byte, n uint64) []byte {
	major <<= 5
	switch {
	case n <= 23:
		return append(buf, major|byte(n))
	case n <= 0xff:
		return append(buf, major|24, byte(n))
	case n <= 0xffff:
		return append(buf, major|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		return append(buf, major|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(buf, major|27,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func appendString(buf []byte, s string) []byte {
	buf = appendHead(buf, majorString, uint64(len(s)))
	return append(buf, s...)
}

func appendBytes(buf []byte, b []byte) []byte {
	buf = appendHead(buf, majorBytes, uint64(len(b)))
	return append(buf, b...)
}

// keyLess implements the DAG-CBOR canonical key ordering (RFC 7049 §3.9):
// sort by the byte length of the CBOR-encoded key first, then lexicographically.
//
// For text-string keys shorter than 24 bytes (which covers all did:plc operation keys),
// the CBOR encoding is a 1-byte head followed by the string bytes, so the encoded length
// equals 1 + len(key). Equal-length keys are resolved lexicographically.
func keyLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keyLess(keys[i], keys[j]) })
	return keys
}
