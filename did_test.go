package did

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasValidDIDSyntax(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid Test Cases
		{"Shortest valid DID", "did:a:1", true},
		{"Simple valid DID", "did:example:123456789abcdefghi", true},
		{"Valid DID with special characters in method-specific-id", "did:example:abc.def-ghi_jkl", true},
		{"Valid DID with multiple colon-separated segments", "did:example:abc:def:ghi:jkl", true},
		{"Valid DID with percent-encoded characters", "did:example:abc%20def%3Aghi", true},
		{"Valid DID with numeric method-specific-id", "did:example:123:456:789", true},
		{"Valid DID with custom method name", "did:methodname:abc:def%20ghi:jkl", true},
		{"Valid DID with mixed characters in method-specific-id", "did:abc123:xyz-789_abc.def", true},
		{"Valid DID with multiple percent-encoded segments", "did:example:abc:def%3Aghi:jkl%20mno", true},
		{"Valid DID with complex method-specific-id", "did:example:abc:def:ghi:jkl%20mno%3Apqr", true},
		{"Valid DID with empty segment in method-specific-id", "did:example:abc:def::ghi", true},
		{"Valid DID with deeply nested segments", "did:example:abc:def:ghi:jkl%20mno%3Apqr%3Astuv", true},
		// Invalid Test Cases
		{"Missing method-specific-id", "did:example", false},
		{"Missing method-name", "did::123456789abcdefghi", false},
		{"Invalid characters in method-name", "did:Example:123456789abcdefghi", false},
		{"Empty method-specific-id", "did:example:", false},
		{"Trailing colon in method-specific-id", "did:example:abc:def:ghi:jkl:", false},
		{"Invalid percent-encoding", "did:example:abc:def:ghi:jkl%ZZ", false},
		{"Incomplete percent-encoding", "did:example:abc:def:ghi:jkl%2", false},
		{"Trailing '%' in pct-encoded", "did:example:abc:def:ghi:jkl%20mno%3Apqr%", false},
		{"Incomplete pct-encoded at the end", "did:example:abc:def:ghi:jkl%20mno%3Apqr%3", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			require.Equal(t, tt.expected, HasValidDIDSyntax(tt.input))
		})
	}
}

func BenchmarkHasValidDIDSyntax(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		HasValidDIDSyntax("did:example:abc:def:ghi:jkl%20mno%3Apqr%3Astuv")
	}
}

func TestHasValidDidUrlSyntax(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid Test Cases
		{"Base DID only", "did:example:123456789abcdefghi", true},
		{"Base DID with path", "did:example:123456789abcdefghi/path/to/resource", true},
		{"Base DID with query", "did:example:123456789abcdefghi?key=value", true},
		{"Base DID with fragment", "did:example:123456789abcdefghi#section1", true},
		{"Base DID with path, query, and fragment", "did:example:123456789abcdefghi/path/to/resource?key=value#section1", true},
		{"Base DID with empty path", "did:example:123456789abcdefghi/", true},
		{"Base DID with percent-encoded path", "did:example:123456789abcdefghi/path%20to%20resource", true},
		{"Base DID with percent-encoded query", "did:example:123456789abcdefghi?key=value%20with%20spaces", true},
		{"Base DID with percent-encoded fragment", "did:example:123456789abcdefghi#section%201", true},

		// Invalid Test Cases
		{"Invalid DID", "did:example", false},                                                              // Base DID is invalid
		{"Invalid DID with path", "did:example:/path/to/resource", false},                                  // Base DID is invalid
		{"Invalid DID with query", "did:example:?key=value", false},                                        // Base DID is invalid
		{"Invalid DID with fragment", "did:example:#section1", false},                                      // Base DID is invalid
		{"Invalid percent-encoding in path", "did:example:123456789abcdefghi/path%ZZto%20resource", false}, // Invalid percent-encoding
		{"Invalid percent-encoding in query", "did:example:123456789abcdefghi?key=value%ZZ", false},        // Invalid percent-encoding
		{"Invalid percent-encoding in fragment", "did:example:123456789abcdefghi#section%ZZ", false},       // Invalid percent-encoding
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, HasValidDidUrlSyntax(tt.input))
		})
	}
}

func BenchmarkHasValidDidUrlSyntax(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		HasValidDidUrlSyntax("did:example:123456789abcdefghi/path/to/resource?key=value#section1")
	}
}
