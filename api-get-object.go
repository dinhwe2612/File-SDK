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
)

// GetObjectOpt configures GetObject call options.
type GetObjectOpt func(*getObjectOptions)

// getObjectOptions holds configuration for GetObject call.
type getObjectOptions struct {
	headers      http.Header
	providerOpts []crypt.ProviderOpt
}

// WithHeaders sets custom HTTP headers for the request.
func WithHeaders(headers http.Header) GetObjectOpt {
	return func(o *getObjectOptions) {
		o.headers = headers
	}
}

// WithProviderOpts sets the provider options for decryption.
func WithProviderOpts(opts ...crypt.ProviderOpt) GetObjectOpt {
	return func(o *getObjectOptions) {
		o.providerOpts = opts
	}
}

// getGetObjectOptions returns the getObjectOptions with defaults applied.
func getGetObjectOptions(opts ...GetObjectOpt) *getObjectOptions {
	options := &getObjectOptions{
		headers:      make(http.Header),
		providerOpts: []crypt.ProviderOpt{},
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}

// ObjectInfo contains information about an object
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
func (c *Client) GetObject(ctx context.Context, bucketName, objectName string, opts ...GetObjectOpt) (*GetObjectResult, error) {
	if bucketName == "" {
		return nil, errors.New("owner DID (bucketName) is required")
	}
	if objectName == "" {
		return nil, errors.New("object name (CID) is required")
	}

	// Build URL for file endpoint - objectName (CID) is used as path parameter
	// The endpoint already includes /api/v1, so we just append /files/{cid}
	targetURL := fmt.Sprintf("%s/files/%s", c.endpoint.String(), objectName)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Parse options
	options := getGetObjectOptions(opts...)

	// Set headers
	c.mergeHeaders(req.Header, options.headers)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	// Defer close resp.Body unless we successfully return it to the caller
	shouldCloseBody := true
	defer func() {
		if shouldCloseBody {
			resp.Body.Close()
		}
	}()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("get object failed: status=%d", resp.StatusCode)
	}

	// Parse object info from headers
	contentType := resp.Header.Get("Content-Type")
	contentLength := resp.ContentLength

	objectInfo := ObjectInfo{
		CID:         objectName,
		Size:        contentLength,
		ContentType: contentType,
		Metadata:    cloneHeader(resp.Header),
	}

	// Check access level from response header (X-Access-Level)
	// The server returns "private" or "public" in X-Access-Level header
	accessLevel := resp.Header.Get("X-Access-Level")

	// Extract capsule from JWT token instead of response header
	var capsule string
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		// Extract JWT token from Authorization header (could be "Bearer <token>" or just "<token>")
		jwtToken := strings.TrimPrefix(authHeader, "Bearer ")
		jwtToken = strings.TrimSpace(jwtToken)

		if jwtToken != "" {
			capsule, _ = credential.CapsuleFromJWT(jwtToken)
		}
	}

	var reader io.ReadCloser = resp.Body

	// If object is private and we have a private key, decrypt
	if accessLevel == "private" {
		if capsule == "" {
			return nil, errors.New("encrypted capsule is missing for private object")
		}

		// Validate ProviderOpts is provided
		if len(options.providerOpts) == 0 {
			return nil, errors.New("provider options are required for private objects (use WithProviderOpts)")
		}

		// Get decryptor from provider
		decryptor, err := c.cryptProvider.NewPreDecryptor(ctx, capsule, options.providerOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryptor: %w", err)
		}

		// Decrypt the stream using a pipe
		pipeReader, pipeWriter := io.Pipe()
		go func() {
			defer pipeWriter.Close()
			if err := decryptor.DecryptStream(ctx, resp.Body, pipeWriter); err != nil {
				pipeWriter.CloseWithError(fmt.Errorf("decrypt stream failed: %w", err))
				return
			}
		}()

		reader = pipeReader
	}

	// Success: we're returning the body to the caller, so don't close it
	shouldCloseBody = false
	return &GetObjectResult{
		Body: reader,
		Info: objectInfo,
	}, nil
}
