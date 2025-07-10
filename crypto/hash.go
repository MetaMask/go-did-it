package crypto

import (
	stdcrypto "crypto"
	"hash"
	"strconv"

	"golang.org/x/crypto/sha3"
)

// As the standard crypto library prohibits from registering additional hash algorithm (like keccak),
// below is essentially an extension of that mechanism to allow it.

func init() {
	RegisterHash(KECCAK_256, sha3.NewLegacyKeccak256)
	RegisterHash(KECCAK_512, sha3.NewLegacyKeccak512)
}

type Hash uint

// HashFunc simply returns the value of h so that [Hash] implements [SignerOpts].
func (h Hash) HashFunc() Hash {
	return h
}

func (h Hash) String() string {
	if h < maxStdHash {
		return stdcrypto.Hash(h).String()
	}

	// Extensions
	switch h {
	case KECCAK_256:
		return "Keccak-256"
	case KECCAK_512:
		return "Keccak-512"

	default:
		return "unknown hash value " + strconv.Itoa(int(h))
	}
}

const (
	// From "crypto"
	MD4         Hash = 1 + iota // import golang.org/x/crypto/md4
	MD5                         // import crypto/md5
	SHA1                        // import crypto/sha1
	SHA224                      // import crypto/sha256
	SHA256                      // import crypto/sha256
	SHA384                      // import crypto/sha512
	SHA512                      // import crypto/sha512
	MD5SHA1                     // no implementation; MD5+SHA1 used for TLS RSA
	RIPEMD160                   // import golang.org/x/crypto/ripemd160
	SHA3_224                    // import golang.org/x/crypto/sha3
	SHA3_256                    // import golang.org/x/crypto/sha3
	SHA3_384                    // import golang.org/x/crypto/sha3
	SHA3_512                    // import golang.org/x/crypto/sha3
	SHA512_224                  // import crypto/sha512
	SHA512_256                  // import crypto/sha512
	BLAKE2s_256                 // import golang.org/x/crypto/blake2s
	BLAKE2b_256                 // import golang.org/x/crypto/blake2b
	BLAKE2b_384                 // import golang.org/x/crypto/blake2b
	BLAKE2b_512                 // import golang.org/x/crypto/blake2b

	maxStdHash

	// Extensions
	KECCAK_256
	KECCAK_512

	maxHash
)

var hashes = make([]func() hash.Hash, maxHash-maxStdHash-1)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 && h < maxStdHash {
		return stdcrypto.Hash(h).New()
	}
	if h > maxStdHash && h < maxHash {
		f := hashes[h-maxStdHash-1]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, f func() hash.Hash) {
	if h >= maxHash {
		panic("crypto: RegisterHash of unknown hash function")
	}
	if h <= maxStdHash {
		panic("crypto: RegisterHash of standard hash function")
	}
	hashes[h-maxStdHash-1] = f
}
