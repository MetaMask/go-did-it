package did

import (
	"context"
	"net/http"

	"github.com/MetaMask/go-did-it/crypto"
)

type ResolutionOpts struct {
	ctx                    context.Context
	keySet                 *crypto.KeySet
	hintVerificationMethod []string
	client                 HttpClient
}

func (opts *ResolutionOpts) Context() context.Context {
	if opts.ctx != nil {
		return opts.ctx
	}
	return context.Background()
}

func (opts *ResolutionOpts) KeySet() *crypto.KeySet {
	if opts.keySet == nil {
		return crypto.DefaultKeySet
	}
	return opts.keySet
}

func (opts *ResolutionOpts) HasVerificationMethodHint(hint string) bool {
	for _, h := range opts.hintVerificationMethod {
		if h == hint {
			return true
		}
	}
	return false
}

func (opts *ResolutionOpts) HttpClient() HttpClient {
	if opts.client != nil {
		return opts.client
	}
	return http.DefaultClient
}

func CollectResolutionOpts(opts []ResolutionOption) ResolutionOpts {
	res := ResolutionOpts{}
	for _, opt := range opts {
		opt(&res)
	}
	return res
}

type ResolutionOption func(opts *ResolutionOpts)

// WithResolutionContext provides a go context to use for the resolution.
// This context can be used for deadline or cancellation.
func WithResolutionContext(ctx context.Context) ResolutionOption {
	return func(opts *ResolutionOpts) {
		opts.ctx = ctx
	}
}

// WithKeySet provides a KeySet, a set of cryptographic key algorithm as
// allowed during resolution. If the DID to resolve has an algorithm not included
// in this set, resolution will fail.
// This is a way for the caller to control what algorithm are deemed safe or expected.
func WithKeySet(keyset *crypto.KeySet) ResolutionOption {
	return func(opts *ResolutionOpts) {
		opts.keySet = keyset
	}
}

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

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WithHttpClient provides an HttpClient to be used during resolution.
func WithHttpClient(client HttpClient) ResolutionOption {
	return func(opts *ResolutionOpts) {
		opts.client = client
	}
}
