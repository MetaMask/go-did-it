package crypto

import (
	"github.com/ucan-wg/go-varsig"
)

type SigningOpts struct {
	hash            Hash
	payloadEncoding varsig.PayloadEncoding

	// if WithVarsig is used
	algo   varsig.Algorithm
	curve  uint64
	keyLen uint64
}

func CollectSigningOptions(opts []SigningOption) SigningOpts {
	res := SigningOpts{}
	for _, opt := range opts {
		opt(&res)
	}
	return res
}

func (opts SigningOpts) HashOrDefault(_default Hash) Hash {
	if opts.hash == 0 {
		return _default
	}
	return opts.hash
}

func (opts SigningOpts) PayloadEncoding() varsig.PayloadEncoding {
	if opts.payloadEncoding == 0 {
		return varsig.PayloadEncodingVerbatim
	}
	return opts.payloadEncoding
}

func (opts SigningOpts) VarsigMatch(algo varsig.Algorithm, curve uint64, keyLength uint64) bool {
	// This is relatively ugly, but we get cyclic import otherwise
	switch opts.algo {
	case 0:
		// not varsig to compare
		return true
	case varsig.AlgorithmECDSA:
		return algo == varsig.AlgorithmECDSA && opts.curve == curve
	case varsig.AlgorithmEdDSA:
		return algo == varsig.AlgorithmEdDSA && opts.curve == curve
	case varsig.AlgorithmRSA:
		return algo == varsig.AlgorithmRSA && opts.keyLen == keyLength
	default:
		panic("unreachable")
	}
}

type SigningOption func(opts *SigningOpts)

// WithSigningHash specify the hash algorithm to be used for signatures
func WithSigningHash(hash Hash) SigningOption {
	return func(opts *SigningOpts) {
		opts.hash = hash
	}
}

// WithPayloadEncoding specify the encoding that was used on the message before signing it.
// This will be included in the resulting varsig.
func WithPayloadEncoding(encoding varsig.PayloadEncoding) SigningOption {
	return func(opts *SigningOpts) {
		opts.payloadEncoding = encoding
	}
}

// WithVarsig configure the signing or verification parameters from a varsig.
// If you use WithVarsig, you should NOT use other options.
func WithVarsig(vsig varsig.Varsig) SigningOption {
	return func(opts *SigningOpts) {
		opts.payloadEncoding = vsig.PayloadEncoding()
		opts.hash = FromVarsigHash(vsig.Hash())
		opts.algo = vsig.Algorithm()
		switch vsig := vsig.(type) {
		case varsig.EdDSAVarsig:
			opts.curve = uint64(vsig.Curve())
		case varsig.ECDSAVarsig:
			opts.curve = uint64(vsig.Curve())
		case varsig.RSAVarsig:
			opts.keyLen = vsig.KeyLength()
		default:
			panic("unreachable")
		}
	}
}
