package filesdk

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dinhwe2612/file-sdk/pkg/crypt"
)

// Client is a minimal S3-compatible client wrapper that follows PutObject/GetObject interface patterns.
// It does not attempt to replicate the full AWS S3 protocol, but provides a custom implementation skeleton
// that allows you to inject custom logic for signing, authentication, encryption, etc.
type Client struct {
	endpoint           *url.URL
	httpClient         *http.Client
	defaultHdrs        http.Header
	cryptProvider      crypt.Provider
	resolverUrl        string
	verificationMethod string
}

const (
	// defaultHTTPTimeout is used when Config.Timeout is zero or negative.
	defaultHTTPTimeout = 30 * time.Second
	// maxErrorBodyBytes is the maximum number of bytes to read from the error response body.
	maxErrorBodyBytes = 1 << 20
)

// Config is used to initialize Client.
type Config struct {
	// Endpoint like https://example.com/api/v1 or http://127.0.0.1:9000.
	Endpoint string
	// Default timeout. If empty, uses 30 seconds.
	Timeout time.Duration
	// Optional default headers. For example X-Owner-Did, Authorization, etc.
	DefaultHeaders http.Header
	// Custom http.Client; if nil, automatically created.
	HTTPClient *http.Client
	// CryptProvider allows customizing how decryptors are constructed for private downloads.
	// If nil, a DefaultProvider (using OwnerPrivateKeyHex) is used.
	CryptProvider crypt.Provider
}

// New creates a Client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("endpoint is required")
	}

	rawEndpoint := cfg.Endpoint
	if !strings.Contains(rawEndpoint, "://") {
		rawEndpoint = "https://" + rawEndpoint
	}

	u, err := url.Parse(rawEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = defaultHTTPTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}

	defaultHdrs := http.Header{}
	for k, v := range cfg.DefaultHeaders {
		cp := make([]string, len(v))
		copy(cp, v)
		defaultHdrs[k] = cp
	}

	// Initialize crypto provider (used by GetObject for private decryption).
	cryptProv := cfg.CryptProvider
	if cryptProv == nil {
		cryptProv = &crypt.DefaultProvider{}
	}

	return &Client{
		endpoint:      u,
		httpClient:    httpClient,
		defaultHdrs:   defaultHdrs,
		cryptProvider: cryptProv,
	}, nil
}

// mergeHeaders merges default headers with caller's custom headers.
func (c *Client) mergeHeaders(dst http.Header, extra http.Header) {
	for k, v := range c.defaultHdrs {
		for _, vv := range v {
			dst.Add(k, vv)
		}
	}
	for k, v := range extra {
		dst.Del(k)
		for _, vv := range v {
			dst.Add(k, vv)
		}
	}
}

// cloneHeader copies response headers to prevent external modification of original headers.
func cloneHeader(src http.Header) http.Header {
	out := make(http.Header, len(src))
	for k, v := range src {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}
