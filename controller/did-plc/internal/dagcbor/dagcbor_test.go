package dagcbor_test

import (
	"encoding/hex"
	"testing"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/controller/did-plc/internal/dagcbor"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	// strip spaces so hex literals can be written with spacing for readability
	clean := ""
	for _, c := range s {
		if c != ' ' {
			clean += string(c)
		}
	}
	b, err := hex.DecodeString(clean)
	require.NoError(t, err)
	return b
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := dagcbor.Encode(v)
	require.NoError(t, err)
	return b
}

func TestNull(t *testing.T) {
	require.Equal(t, mustHex(t, "f6"), encode(t, nil))
}

func TestString(t *testing.T) {
	// Empty string: major(3)<<5 | length 0 = 0x60
	require.Equal(t, mustHex(t, "60"), encode(t, ""))

	// "hello" (5 bytes): 0x65 + UTF-8
	require.Equal(t, mustHex(t, "65 68656c6c6f"), encode(t, "hello"))

	// 23-byte string: single-byte head still fits (0x60|23 = 0x77)
	s23 := "abcdefghijklmnopqrstuvw"
	require.Len(t, s23, 23)
	got := encode(t, s23)
	require.Equal(t, byte(0x77), got[0])
	require.Equal(t, []byte(s23), got[1:])

	// 24-byte string: two-byte head (major|24, length)
	s24 := "abcdefghijklmnopqrstuvwx"
	require.Len(t, s24, 24)
	got = encode(t, s24)
	require.Equal(t, []byte{0x60 | 24, 24}, got[:2])
	require.Equal(t, []byte(s24), got[2:])
}

func TestStringArray(t *testing.T) {
	// Empty array: 0x80
	require.Equal(t, mustHex(t, "80"), encode(t, []string{}))
	require.Equal(t, mustHex(t, "80"), encode(t, ([]string)(nil)))

	// ["a", "b"]: 0x82 + "a" + "b"
	require.Equal(t, mustHex(t, "82 6161 6162"), encode(t, []string{"a", "b"}))
}

func TestStringMapKeyOrdering(t *testing.T) {
	// Keys sorted by encoded length first, then lexicographically:
	// "a"(len 1) < "bb"(len 2) < "ccc"(len 3)
	m := map[string]string{"ccc": "3", "a": "1", "bb": "2"}
	got := encode(t, m)
	expected := mustHex(t,
		"a3"+ // map(3)
			"6161"+"6131"+ // "a" → "1"
			"626262"+"6132"+ // "bb" → "2"
			"63636363"+"6133") // "ccc" → "3"
	require.Equal(t, expected, got)
}

func TestStringMapSameLengthLexOrder(t *testing.T) {
	// "ab" and "ba" have equal length; "ab" < "ba" lexicographically
	m := map[string]string{"ba": "2", "ab": "1"}
	got := encode(t, m)
	expected := mustHex(t,
		"a2"+ // map(2)
			"626162"+"6131"+ // "ab" → "1"
			"626261"+"6132") // "ba" → "2"
	require.Equal(t, expected, got)
}

func TestNestedMap(t *testing.T) {
	m := map[string]any{
		"x": map[string]any{"b": "2", "a": "1"},
	}
	got := encode(t, m)
	expected := mustHex(t,
		"a1"+ // map(1)
			"6178"+ // key "x"
			"a2"+ // map(2)
			"6161"+"6131"+ // "a"→"1"
			"6162"+"6132") // "b"→"2"
	require.Equal(t, expected, got)
}

func TestCIDLink(t *testing.T) {
	// Construct a CIDv1 dag-cbor sha2-256 from a known digest (32 zero bytes).
	digest := make([]byte, 32)
	multihash, err := mh.Encode(digest, mh.SHA2_256)
	require.NoError(t, err)
	c := cid.NewCidV1(cid.DagCBOR, multihash)

	got := encode(t, c)

	// Expected encoding:
	//   tag(42):      d8 2a
	//   bytes(1+N):   58 (1+len(c.Bytes())) then content
	//   prefix byte:  00
	//   CID bytes:    c.Bytes()
	raw := c.Bytes()
	prefixed := append([]byte{0x00}, raw...)
	want := []byte{0xd8, 0x2a}
	want = append(want, 0x58, byte(len(prefixed)))
	want = append(want, prefixed...)
	require.Equal(t, want, got)
}

func TestPlcOperationKeyOrder(t *testing.T) {
	// Canonical order for the 6 unsigned plc_operation keys:
	// "prev"(4) < "type"(4,lex) < "services"(8) < "alsoKnownAs"(11) < "rotationKeys"(12) < "verificationMethods"(19)
	m := map[string]any{
		"type":                "plc_operation",
		"rotationKeys":        []string{},
		"verificationMethods": map[string]string{},
		"alsoKnownAs":         []string{},
		"services":            map[string]any{},
		"prev":                nil,
	}
	got := encode(t, m)
	keys := extractMapKeys(t, got)
	require.Equal(t,
		[]string{"prev", "type", "services", "alsoKnownAs", "rotationKeys", "verificationMethods"},
		keys)
}

func TestUnsupportedType(t *testing.T) {
	_, err := dagcbor.Encode(42)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported type")
}

// extractMapKeys decodes text-string map keys from a CBOR-encoded top-level map.
func extractMapKeys(t *testing.T, b []byte) []string {
	t.Helper()
	require.NotEmpty(t, b)
	require.Equal(t, byte(0xa0), b[0]&0xe0, "expected major type 5 (map)")
	n := int(b[0] & 0x1f)
	require.Less(t, n, 24, "multi-byte map lengths not handled in this helper")

	pos := 1
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		require.Equal(t, byte(0x60), b[pos]&0xe0, "expected text-string key")
		klen := int(b[pos] & 0x1f)
		pos++
		keys = append(keys, string(b[pos:pos+klen]))
		pos += klen
		pos = skipValue(t, b, pos)
	}
	return keys
}

func skipValue(t *testing.T, b []byte, pos int) int {
	t.Helper()
	require.Less(t, pos, len(b))
	head := b[pos]
	major := head >> 5
	info := head & 0x1f
	pos++
	var length int
	switch {
	case info <= 23:
		length = int(info)
	case info == 24:
		length = int(b[pos])
		pos++
	case info == 25:
		length = int(b[pos])<<8 | int(b[pos+1])
		pos += 2
	default:
		t.Fatalf("unexpected additional info %d", info)
	}
	switch major {
	case 0: // uint
	case 2: // bytes
		pos += length
	case 3: // string
		pos += length
	case 4: // array
		for i := 0; i < length; i++ {
			pos = skipValue(t, b, pos)
		}
	case 5: // map
		for i := 0; i < length*2; i++ {
			pos = skipValue(t, b, pos)
		}
	case 6: // tag — skip tag number (already consumed as length) then the tagged value
		pos = skipValue(t, b, pos)
	case 7: // simple / float; null = 0xf6, no following bytes
	default:
		t.Fatalf("unexpected major type %d", major)
	}
	return pos
}
