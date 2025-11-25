package filesdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dinhwe2612/file-sdk/pkg/crypt"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
	"github.com/pilacorp/nda-auth-sdk/auth"
	"github.com/pilacorp/nda-auth-sdk/provider"
	"github.com/pilacorp/nda-auth-sdk/provider/ecdsa"
)

// Client is a minimal S3-compatible client wrapper that follows PutObject/GetObject interface patterns.
// It does not attempt to replicate the full AWS S3 protocol, but provides a custom implementation skeleton
// that allows you to inject custom logic for signing, authentication, encryption, etc.
type Client struct {
	endpoint            *url.URL
	httpClient          *http.Client
	defaultHdrs         http.Header
	cryptProvider       crypt.Provider
	authClient          auth.Auth
	resolver            *verificationmethod.Resolver
	applicationDID      string
	gatewayTrustJWT     string
	accessibleSchemaURL string
}

// AccessType represents the access type of an object
type AccessType string

const (
	// Common header keys
	headerAuthorization = "Authorization"

	// AccessTypePublic indicates the object is public (no encryption)
	AccessTypePublic AccessType = "public"

	// AccessTypePrivate indicates the object is private (encrypted)
	AccessTypePrivate AccessType = "private"

	// copyBufferSize is the buffer size used for copying data to multipart form.
	// 64KB is a good balance between memory usage and performance for file uploads.
	copyBufferSize = 64 * 1024

	// encryptorChunkSize is the chunk size used for PRE encryption.
	// 1MB chunk size provides good performance for encrypted file uploads.
	encryptorChunkSize = 1 << 20 // 1MB

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
	// Auth client for extracting VC JWTs and creating VP tokens.
	AuthClient auth.Auth
	// Accessible schema URL for owner file credentials.

	// DID Resolver URL for resolving public keys from verification method URLs.
	DIDResolverURL string
	// Application DID for creating VP token.
	ApplicationDID string
	// Gateway trust JWT for creating VP token.
	GatewayTrustJWT string
	// Accessible schema URL for owner file credentials.
	AccessibleSchemaURL string
}

// New creates a Client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("endpoint is required")
	}

	if strings.TrimSpace(cfg.AccessibleSchemaURL) == "" {
		return nil, errors.New("accessible schema URL is required")
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

	// Initialize resolver
	resolver := verificationmethod.NewResolver(cfg.DIDResolverURL)

	authClient := cfg.AuthClient
	if authClient == nil {
		defaultProvider := ecdsa.NewProviderPriv()
		authClient = auth.NewAuth(defaultProvider, cfg.DIDResolverURL)
	}

	return &Client{
		endpoint:            u,
		httpClient:          httpClient,
		defaultHdrs:         defaultHdrs,
		cryptProvider:       cryptProv,
		authClient:          authClient,
		applicationDID:      cfg.ApplicationDID,
		gatewayTrustJWT:     cfg.GatewayTrustJWT,
		resolver:            resolver,
		accessibleSchemaURL: cfg.AccessibleSchemaURL,
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

// buildVPAuthorization verifies the caller authorization header and produces a VP token.
// It returns the new VP token along with the normalized caller authorization (used for capsule extraction).
func (c *Client) buildVPAuthorization(
	ctx context.Context,
	rawAuthorization string,
	expectedRequester string,
	signOptions ...provider.SignOption,
) (string, string, error) {
	authorization := strings.TrimSpace(rawAuthorization)
	if authorization == "" {
		return "", "", errors.New("authorization header is required")
	}

	_, requester, vcJWTs, err := c.authClient.VerifyToken(ctx, authorization)
	if err != nil {
		return "", "", fmt.Errorf("filesdk: failed to verify authorization: %w", err)
	}
	if expectedRequester != "" && requester != expectedRequester {
		return "", "", fmt.Errorf(
			"filesdk: requester DID %q does not match issuer DID %q",
			requester, expectedRequester,
		)
	}

	vcJWTs = append(vcJWTs, c.gatewayTrustJWT)

	vpToken, err := c.authClient.CreateToken(ctx, vcJWTs, c.applicationDID, signOptions...)
	if err != nil {
		return "", "", fmt.Errorf("filesdk: failed to create VP token: %w", err)
	}

	return vpToken, authorization, nil
}
