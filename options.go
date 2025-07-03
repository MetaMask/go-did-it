package did

type ResolutionOpts struct {
	hintVerificationMethod []string
}

func (opts *ResolutionOpts) HasVerificationMethodHint(hint string) bool {
	for _, h := range opts.hintVerificationMethod {
		if h == hint {
			return true
		}
	}
	return false
}

func CollectResolutionOpts(opts []ResolutionOption) ResolutionOpts {
	res := ResolutionOpts{}
	for _, opt := range opts {
		opt(&res)
	}
	return res
}

type ResolutionOption func(opts *ResolutionOpts)

// WithResolutionHintVerificationMethod adds a hint for the type of verification method to be used
// when resolving and constructing the DID Document, if possible.
// Hints are expected to be VerificationMethod string types, like ed25519vm.Type.
func WithResolutionHintVerificationMethod(hint string) ResolutionOption {
	return func(opts *ResolutionOpts) {
		if len(hint) == 0 {
			return
		}
		for _, s := range opts.hintVerificationMethod {
			if s == hint {
				return
			}
		}
		opts.hintVerificationMethod = append(opts.hintVerificationMethod, hint)
	}
}
