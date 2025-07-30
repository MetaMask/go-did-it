package crypto

import (
	stdcrypto "crypto"
	"hash"
	"strconv"

	"github.com/ucan-wg/go-varsig"
	"golang.org/x/crypto/sha3"
)

// As the standard crypto library prohibits from registering additional hash algorithm (like keccak),
// below is essentially an extension of that mechanism to allow it.

type Hash uint

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

// HashFunc simply returns the value of h so that [Hash] implements [SignerOpts].
func (h Hash) HashFunc() Hash {
	return h
}

func (h Hash) String() string {
	if h < maxStdHash {
		return stdcrypto.Hash(h).String()
	}
	if h > maxStdHash && h < maxHash {
		return hashNames[h-maxStdHash-1]
	}
	panic("requested hash #" + strconv.Itoa(int(h)) + " is unavailable")
}

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 && h < maxStdHash {
		return stdcrypto.Hash(h).New()
	}
	if h > maxStdHash && h < maxHash {
		f := hashFns[h-maxStdHash-1]
		if f != nil {
			return f()
		}
	}
	panic("requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

func (h Hash) ToVarsigHash() varsig.Hash {
	if h == MD5SHA1 {
		panic("no multihash/multicodec value exists for MD5+SHA1")
	}
	if h < maxHash {
		return hashVarsigs[h]
	}
	panic("requested hash #" + strconv.Itoa(int(h)) + " is unavailable")
}

func FromVarsigHash(h varsig.Hash) Hash {
	switch h {
	case varsig.HashMd4:
		return MD4
	case varsig.HashMd5:
		return MD5
	case varsig.HashSha1:
		return SHA1
	case varsig.HashSha2_224:
		return SHA224
	case varsig.HashSha2_256:
		return SHA256
	case varsig.HashSha2_384:
		return SHA384
	case varsig.HashSha2_512:
		return SHA512
	case varsig.HashRipemd_160:
		return RIPEMD160
	case varsig.HashSha3_224:
		return SHA3_224
	case varsig.HashSha3_256:
		return SHA3_256
	case varsig.HashSha3_384:
		return SHA3_384
	case varsig.HashSha3_512:
		return SHA3_512
	case varsig.HashSha512_224:
		return SHA512_224
	case varsig.HashSha512_256:
		return SHA512_256
	case varsig.HashBlake2s_256:
		return BLAKE2s_256
	case varsig.HashBlake2b_256:
		return BLAKE2b_256
	case varsig.HashBlake2b_384:
		return BLAKE2b_384
	case varsig.HashBlake2b_512:
		return BLAKE2b_512
	case varsig.HashKeccak_256:
		return KECCAK_256
	case varsig.HashKeccak_512:
		return KECCAK_512
	default:
		panic("varsig " + strconv.Itoa(int(h)) + " is not supported")
	}
}

var hashNames = []string{
	"Keccak-256",
	"Keccak-512",
}
var hashFns = []func() hash.Hash{
	sha3.NewLegacyKeccak256,
	sha3.NewLegacyKeccak512,
}
var hashVarsigs = []varsig.Hash{
	0, // undef
	varsig.HashMd4,
	varsig.HashMd5,
	varsig.HashSha1,
	varsig.HashSha2_224,
	varsig.HashSha2_256,
	varsig.HashSha2_384,
	varsig.HashSha2_512,
	0, // missing MD5SHA1
	varsig.HashRipemd_160,
	varsig.HashSha3_224,
	varsig.HashSha3_256,
	varsig.HashSha3_384,
	varsig.HashSha3_512,
	varsig.HashSha512_224,
	varsig.HashSha512_256,
	varsig.HashBlake2s_256,
	varsig.HashBlake2b_256,
	varsig.HashBlake2b_384,
	varsig.HashBlake2b_512,
	0, // maxStdHash
	varsig.HashKeccak_256,
	varsig.HashKeccak_512,
}
