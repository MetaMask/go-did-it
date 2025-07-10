package crypto

type SigningOpts struct {
	Hash Hash
}

func CollectSigningOptions(opts []SigningOption) SigningOpts {
	res := SigningOpts{}
	for _, opt := range opts {
		opt(&res)
	}
	return res
}

func (opts SigningOpts) HashOrDefault(_default Hash) Hash {
	if opts.Hash == 0 {
		return _default
	}
	return opts.Hash
}

type SigningOption func(opts *SigningOpts)

// WithSigningHash specify the hash algorithm to be used for signatures
func WithSigningHash(hash Hash) SigningOption {
	return func(opts *SigningOpts) {
		opts.Hash = hash
	}
}
