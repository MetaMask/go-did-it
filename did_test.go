package did_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto/x25519"
	_ "github.com/INFURA/go-did/methods/did-key"
)

func Example_signature() {
	// errors need to be handled

	// 1) Parse the DID string into a DID object
	d, _ := did.Parse("did:key:z6MknwcywUtTy2ADJQ8FH1GcSySKPyKDmyzT4rPEE84XREse")

	// 2) Resolve to the DID Document
	doc, _ := d.Document()

	// 3) Use the appropriate verification method (ex: verify a signature for authentication purpose)
	sig, _ := base64.StdEncoding.DecodeString("nhpkr5a7juUM2eDpDRSJVdEE++0SYqaZXHtuvyafVFUx8zsOdDSrij+vHmd/ARwUOmi/ysmSD+b3K9WTBtmmBQ==")
	if ok, method := did.TryAllVerify(doc.Authentication(), []byte("message"), sig); ok {
		fmt.Println("Signature is valid, verified with method:", method.Type(), method.ID())
	} else {
		fmt.Println("Signature is invalid")
	}

	// Output: Signature is valid, verified with method: Ed25519VerificationKey2020 did:key:z6MknwcywUtTy2ADJQ8FH1GcSySKPyKDmyzT4rPEE84XREse#z6MknwcywUtTy2ADJQ8FH1GcSySKPyKDmyzT4rPEE84XREse
}

func Example_keyAgreement() {
	// errors need to be handled

	// 1) We have a private key for Alice
	privAliceBytes, _ := base64.StdEncoding.DecodeString("fNOf3xWjFZYGYWixorM5+JR+u/2Udnc9Zw5+9rSvjqo=")
	privAlice, _ := x25519.PrivateKeyFromBytes(privAliceBytes)

	// 2) We resolve the DID Document for Bob
	dBob, _ := did.Parse("did:key:z6MkgRNXpJRbEE6FoXhT8KWHwJo4KyzFo1FdSEFpRLh5vuXZ")
	docBob, _ := dBob.Document()

	// 3) We perform the key agreement
	key, method, _ := did.FindMatchingKeyAgreement(docBob.KeyAgreement(), privAlice)

	fmt.Println("Shared key:", base64.StdEncoding.EncodeToString(key))
	fmt.Println("Verification method used:", method.Type(), method.ID())

	// Output: Shared key: 7G1qwS/gn5W1hxBtObHc3F0jA7m2vuXkLJJ32yBuHVQ=
	// Verification method used: X25519KeyAgreementKey2020 did:key:z6MkgRNXpJRbEE6FoXhT8KWHwJo4KyzFo1FdSEFpRLh5vuXZ#z6LSjeQx2VkXz8yirhrYJv8uicu9BBaeYU3Q1D9sFBovhmPF
}

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
			require.Equal(t, tt.expected, did.HasValidDIDSyntax(tt.input))
		})
	}
}

func BenchmarkHasValidDIDSyntax(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		did.HasValidDIDSyntax("did:example:abc:def:ghi:jkl%20mno%3Apqr%3Astuv")
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
			require.Equal(t, tt.expected, did.HasValidDidUrlSyntax(tt.input))
		})
	}
}

func BenchmarkHasValidDidUrlSyntax(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		did.HasValidDidUrlSyntax("did:example:123456789abcdefghi/path/to/resource?key=value#section1")
	}
}
