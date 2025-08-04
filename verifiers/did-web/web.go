package did_web

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/document"
)

// Specification: https://w3c-ccg.github.io/did-method-web/

func init() {
	did.RegisterMethod("web", Decode)
}

var _ did.DID = DidWeb{}

type DidWeb struct {
	msi   string // method-specific identifier, i.e. "12345" in "did:web:12345"
	parts []string
}

func Decode(identifier string) (did.DID, error) {
	const webPrefix = "did:web:"

	if !strings.HasPrefix(identifier, webPrefix) {
		return nil, fmt.Errorf("%w: must start with 'did:web'", did.ErrInvalidDid)
	}

	msi := identifier[len(webPrefix):]
	if len(msi) == 0 {
		return nil, fmt.Errorf("%w: empty did:web identifier", did.ErrInvalidDid)
	}

	parts := strings.Split(msi, ":")

	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	if !isValidHost(host) {
		return nil, fmt.Errorf("%w: invalid host", did.ErrInvalidDid)
	}
	parts[0] = host

	for i := 1; i < len(parts); i++ {
		parts[i], err = url.PathUnescape(parts[i])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
		}
	}

	return DidWeb{msi: msi, parts: parts}, nil
}

func (d DidWeb) Method() string {
	return "web"
}

func (d DidWeb) Document(opts ...did.ResolutionOption) (did.Document, error) {
	params := did.CollectResolutionOpts(opts)

	var u string
	var err error

	if len(d.parts) == 1 {
		u, err = url.JoinPath("https://"+d.parts[0], ".well-known/did.json")
	} else {
		parts := append(d.parts[1:], "did.json")
		u, err = url.JoinPath("https://"+d.parts[0], parts...)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrResolutionFailure, err)
	}

	req, err := http.NewRequestWithContext(params.Context(), "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrResolutionFailure, err)
	}
	req.Header.Set("User-Agent", "go-did-it")

	res, err := params.HttpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrResolutionFailure, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", did.ErrResolutionFailure, res.StatusCode)
	}

	// limit at 1MB to avoid abuse
	limiter := io.LimitReader(res.Body, 1<<20)

	doc, err := document.FromJsonReader(limiter)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrResolutionFailure, err)
	}

	if doc.ID() != d.String() {
		return nil, fmt.Errorf("%w: did:web identifier mismatch", did.ErrResolutionFailure)
	}

	return doc, nil
}

func (d DidWeb) String() string {
	return fmt.Sprintf("did:web:%s", d.msi)
}

func (d DidWeb) ResolutionIsExpensive() bool {
	// requires an external HTTP request
	return true
}

func (d DidWeb) Equal(d2 did.DID) bool {
	if d2, ok := d2.(DidWeb); ok {
		return d.msi == d2.msi
	}
	if d2, ok := d2.(*DidWeb); ok {
		return d.msi == d2.msi
	}
	return false
}

var domainRegexp = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$`)

func isValidHost(host string) bool {
	h, port, err := net.SplitHostPort(host)
	if err == nil {
		portInt, err := strconv.Atoi(port)
		if err != nil {
			return false
		}
		if portInt < 0 || portInt > 65535 {
			return false
		}
		host = h
	}
	if !domainRegexp.MatchString(host) {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		// disallow IP addresses
		return false
	}
	return true
}
