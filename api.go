package filesdk

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dinhwe2612/file-sdk/pkg/crypt"
	"github.com/pilacorp/nda-auth-sdk/auth"
)

var applicationDID, gatewayTrustJWT string

func SetApplicationDID(did string) {
	applicationDID = did
}

func SetGatewayTrustJWT(jwt string) {
	gatewayTrustJWT = jwt
}

// Resolver interface for resolving public keys from verification method URLs
type Resolver interface {
	GetPublicKey(verificationMethodURL string) (string, error)
}

// Client is a minimal S3-compatible client wrapper that follows PutObject/GetObject interface patterns.
// It does not attempt to replicate the full AWS S3 protocol, but provides a custom implementation skeleton
// that allows you to inject custom logic for signing, authentication, encryption, etc.
type Client struct {
	endpoint      *url.URL
	httpClient    *http.Client
	defaultHdrs   http.Header
	cryptProvider crypt.Provider
	resolver      Resolver
	authClient    auth.Auth
}

const (
	// defaultHTTPTimeout is used when Config.Timeout is zero or negative.
	defaultHTTPTimeout = 30 * time.Second
	// maxErrorBodyBytes is the maximum number of bytes to read from the error response body.
	maxErrorBodyBytes = 1 << 20
)

// Config is used to initialize Client.
type Config struct {
	// Endpoint is the gateway domain (e.g., https://example.com or http://127.0.0.1:9000).
	// The SDK will automatically append /api/v1 to the path if not already present.
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
	// Resolver is required for resolving public keys from verification method URLs.
	// Used for private file uploads to encrypt data.
	Resolver Resolver
	// Auth
	Auth auth.Auth
}

// New creates a Client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("endpoint is required")
	}

	rawEndpoint := cfg.Endpoint

	u, err := url.Parse(rawEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	// Automatically append /api/v1 if path is empty or just "/"
	// If user provides just the domain, we add the API path prefix
	path := strings.TrimSuffix(u.Path, "/")
	if path == "" || path == "/" {
		u.Path = "/api/v1"
	} else if !strings.HasPrefix(path, "/api/v1") {
		// If path doesn't start with /api/v1, prepend it
		u.Path = "/api/v1" + u.Path
	} else {
		// Path already contains /api/v1, keep it as is
		u.Path = path
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

	// Validate resolver is provided
	if cfg.Resolver == nil {
		return nil, errors.New("resolver is required")
	}

	return &Client{
		endpoint:      u,
		httpClient:    httpClient,
		defaultHdrs:   defaultHdrs,
		cryptProvider: cryptProv,
		resolver:      cfg.Resolver,
		authClient:    cfg.Auth,
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
