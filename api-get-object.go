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

// WithDecryptionProviderOptions sets PRE decryptor/provider options.
func WithDecryptionProviderOptions(opts ...crypt.ProviderOpt) GetObjectOpt {
	return func(o *getObjectOptions) {
		o.providerOpts = append(o.providerOpts, opts...)
	}
}

// WithGetApplicationSigners sets application signing options used when creating download VP tokens.
func WithGetApplicationSigners(opts ...provider.SignOption) GetObjectOpt {
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
	options := getGetObjectOptions(opts...)

	if bucketName == "" {
		return nil, errors.New("owner DID (bucketName) is required")
	}
	if objectName == "" {
		return nil, errors.New("object name (CID) is required")
	}
	if c.applicationDID == "" {
		return nil, errors.New("application DID is not configured")
	}
	if c.gatewayTrustJWT == "" {
		return nil, errors.New("gateway trust JWT is not configured")
	}
	if c.authClient == nil {
		return nil, errors.New("auth client is not configured")
	}

	// Build request & headers
	targetURL := fmt.Sprintf("%s/files/%s", c.endpoint.String(), objectName)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to create request: %w", err)
	}

	// Set headers
	c.mergeHeaders(req.Header, options.headers)

	// Ensure owner DID header is propagated if caller provided bucket
	if req.Header.Get(headerOwnerDID) == "" {
		req.Header.Set(headerOwnerDID, bucketName)
	}

	// Get authorization from headers
	authorization := strings.TrimSpace(req.Header.Get(headerAuthorization))
	if authorization == "" {
		return nil, errors.New("authorization header is required")
	}

	vpToken, normalizedAuthorization, err := c.buildVPAuthorization(ctx, authorization, "", options.signOptions...)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to build VP authorization: %w", err)
	}

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
	capsule, capErr := credential.CapsuleFromJWT(normalizedAuthorization)
	if capErr != nil {
		// We treat failure to extract capsule as "no capsule" → public object.
		capsule = ""
	}

	// Default reader: raw response body
	var reader io.ReadCloser = respBody

	// If object is private and we have a capsule, decrypt
	if capsule != "" {
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
	}

	// Don't close body here, let the caller close it
	shouldCloseBody = false

	return &GetObjectResult{
		Body: reader,
		Info: objectInfo,
	}, nil
}
