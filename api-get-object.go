package filesdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dinhwe2612/file-sdk/pkg/credential"
	"github.com/dinhwe2612/file-sdk/pkg/crypt"
	"github.com/pilacorp/nda-auth-sdk/provider"
)

// Common header keys
const (
	headerOwnerDID      = "X-Owner-Did"
	headerAuthorization = "Authorization"
)

// GetObjectOpt configures GetObject call options.
type GetObjectOpt func(*getObjectOptions)

// getObjectOptions holds configuration for GetObject call.
type getObjectOptions struct {
	headers      http.Header
	providerOpts []crypt.ProviderOpt
	signOptions  []provider.SignOption
}

// WithGetHeaders sets custom HTTP headers for the request.
func WithGetHeaders(headers http.Header) GetObjectOpt {
	return func(o *getObjectOptions) {
		// Defensive copy to avoid caller mutating after the fact
		if headers == nil {
			o.headers = make(http.Header)
			return
		}
		o.headers = cloneHeader(headers)
	}
}

// WithProviderOpts sets the provider options for decryption.
func WithProviderOpts(opts ...crypt.ProviderOpt) GetObjectOpt {
	return func(o *getObjectOptions) {
		o.providerOpts = append(o.providerOpts, opts...)
	}
}

// WithGetObjectSignOptions sets custom sign options when creating VP token.
func WithGetObjectSignOptions(opts ...provider.SignOption) GetObjectOpt {
	return func(o *getObjectOptions) {
		o.signOptions = append(o.signOptions, opts...)
	}
}

// getGetObjectOptions returns the getObjectOptions with defaults applied.
func getGetObjectOptions(opts ...GetObjectOpt) *getObjectOptions {
	options := &getObjectOptions{
		headers:      make(http.Header),
		providerOpts: nil,
		signOptions:  nil,
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}

// ObjectInfo contains information about an object.
type ObjectInfo struct {
	CID         string
	Size        int64
	ContentType string
	Metadata    http.Header
}

// GetObjectResult represents the result of a GetObject operation.
// It contains the object data as an io.ReadCloser and metadata.
type GetObjectResult struct {
	// Body is the object data stream. The caller must close it when done.
	Body io.ReadCloser
	// Info contains the object metadata.
	Info ObjectInfo
}

// GetObject retrieves an object from storage.
// bucketName represents the owner DID, objectName is the CID.
// Returns a GetObjectResult containing the object data stream and metadata.
// The caller must close the Body when done reading.
func (c *Client) GetObject(
	ctx context.Context,
	bucketName, objectName string,
	opts ...GetObjectOpt,
) (*GetObjectResult, error) {
	if bucketName == "" {
		return nil, errors.New("owner DID (bucketName) is required")
	}
	if objectName == "" {
		return nil, errors.New("object name (CID) is required")
	}
	if c.authClient == nil {
		return nil, errors.New("auth client is not configured")
	}
	if applicationDID == "" {
		return nil, errors.New("application DID is not configured (use SetApplicationDID)")
	}
	if gatewayTrustJWT == "" {
		return nil, errors.New("gateway trust JWT is not configured (use SetGatewayTrustJWT)")
	}

	// Build URL for file endpoint - objectName (CID) is used as path parameter.
	// The endpoint already includes /api/v1, so we just append /files/{cid}.
	targetURL := fmt.Sprintf("%s/files/%s", c.endpoint.String(), objectName)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to create request: %w", err)
	}

	// Parse options
	options := getGetObjectOptions(opts...)

	// Set headers
	c.mergeHeaders(req.Header, options.headers)

	// Ensure owner DID header is propagated if caller provided bucket
	if req.Header.Get(headerOwnerDID) == "" {
		req.Header.Set(headerOwnerDID, bucketName)
	}

	// Capture caller-provided Authorization header before we overwrite it
	rawAuthorization := strings.TrimSpace(req.Header.Get(headerAuthorization))
	if rawAuthorization == "" {
		return nil, errors.New("authorization header is required")
	}

	// Verify authorization
	_, _, vcJWTs, err := c.authClient.VerifyToken(ctx, rawAuthorization)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to verify authorization: %w", err)
	}

	// Append VC JWTs to headers
	vcJWTs = append(vcJWTs, gatewayTrustJWT)

	// Create VP token
	vpToken, err := c.authClient.CreateToken(ctx, vcJWTs, applicationDID, options.signOptions...)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to create VP token: %w", err)
	}

	// Some implementations may return the token with surrounding quotes; normalize it.
	vpToken = strings.TrimSpace(vpToken)
	vpToken = strings.Trim(vpToken, `"`)

	req.Header.Set(headerAuthorization, vpToken)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to get object: %w", err)
	}

	respBody := resp.Body
	shouldCloseBody := true
	defer func() {
		if shouldCloseBody && respBody != nil {
			respBody.Close()
		}
	}()

	if resp.StatusCode >= http.StatusBadRequest {
		// Optional: could read and include response body snippet for easier debugging
		return nil, fmt.Errorf("filesdk: get object failed: status=%d", resp.StatusCode)
	}

	// Parse object info from headers
	objectInfo := ObjectInfo{
		CID:         objectName,
		Size:        resp.ContentLength,
		ContentType: resp.Header.Get("Content-Type"),
		Metadata:    cloneHeader(resp.Header),
	}

	// Extract capsule from *original* bearer token to detect private objects.
	capsule, capErr := credential.CapsuleFromJWT(rawAuthorization)
	if capErr != nil {
		// We treat failure to extract capsule as "no capsule" → public object.
		capsule = ""
	}
	isPrivate := capsule != ""

	// Default reader: raw response body
	var reader io.ReadCloser = respBody

	// If object is private and we have a capsule, decrypt
	if isPrivate {
		if len(options.providerOpts) == 0 {
			return nil, errors.New("provider options are required for private objects (use WithProviderOpts)")
		}

		// Get decryptor from provider
		decryptor, err := c.cryptProvider.NewPreDecryptor(ctx, capsule, options.providerOpts...)
		if err != nil {
			return nil, fmt.Errorf("filesdk: failed to create decryptor: %w", err)
		}

		pipeReader, pipeWriter := io.Pipe()

		// Decrypt in a background goroutine.
		go func(body io.ReadCloser) {
			defer body.Close()

			if err := decryptor.DecryptStream(ctx, body, pipeWriter); err != nil {
				_ = pipeWriter.CloseWithError(fmt.Errorf("filesdk: decrypt stream failed: %w", err))
				return
			}
			_ = pipeWriter.Close()
		}(respBody)

		reader = pipeReader

		// We hand off responsibility for closing respBody to the goroutine above.
		shouldCloseBody = false
	} else {
		// For public objects, caller takes ownership of closing resp.Body
		shouldCloseBody = false
	}

	return &GetObjectResult{
		Body: reader,
		Info: objectInfo,
	}, nil
}
