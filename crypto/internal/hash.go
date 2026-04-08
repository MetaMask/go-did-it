package helpers

import "hash"

var _ hash.Hash = &preHashedHasher{}

// preHashedHasher is an identity hash.Hash: Write accumulates bytes, Sum returns them as-is.
// Used with PREHASHED to pass a pre-computed digest through the standard hashing pattern
// without any additional transformation.
type preHashedHasher struct {
	buf []byte
}

func NewPreHashedHasher() hash.Hash {
	return &preHashedHasher{}
}

func (h *preHashedHasher) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

func (h *preHashedHasher) Sum(b []byte) []byte {
	return append(b, h.buf...)
}

func (h *preHashedHasher) Reset() {
	h.buf = h.buf[:0]
}

func (h *preHashedHasher) Size() int {
	return -1
}

func (h *preHashedHasher) BlockSize() int {
	return 1
}
