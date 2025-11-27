package filesdk

import (
	"context"
	"encoding/hex"
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
	providerOpts []crypt.ProviderOpt
	signOptions  []provider.SignOption
}

// WithDecryptPrivKeyHex sets PRE decryptor/provider options.
func WithDecryptPrivKeyHex(privKeyHex string) GetObjectOpt {
	return func(o *getObjectOptions) {
		o.providerOpts = append(o.providerOpts, crypt.WithPrivKeyHex(privKeyHex))
	}
}

// WithDownloadApplicationPrivKeyHex sets application signing options used when creating download VP tokens.
func WithDownloadApplicationPrivKeyHex(privKeyHex string) GetObjectOpt {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return func(o *getObjectOptions) {
			// Error will be caught when hex is decoded - this is a no-op
		}
	}

	return func(o *getObjectOptions) {
		o.signOptions = append(o.signOptions, provider.WithPrivateKey(privKeyBytes))
	}
}

// getGetObjectOptions returns the getObjectOptions with defaults applied.
func getGetObjectOptions(opts ...GetObjectOpt) *getObjectOptions {
	options := &getObjectOptions{
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

// GetObjectInput represents the input for a GetObject operation.
// It contains the bucket, key, and metadata.
type GetObjectInput struct {
	// The bucket name
	Bucket *string
	// The object key (CID)
	Key *string
	// The object metadata
	Metadata map[string]string
}

// GetObjectOutput represents the result of a GetObject operation.
// It contains the object data as an io.ReadCloser and metadata.
type GetObjectOutput struct {
	// Body is the object data stream. The caller must close it when done.
	Body io.ReadCloser
	// Metadata contains the object metadata.
	Metadata map[string]string
}

// GetObject retrieves an object from storage.
// Bucket represents the ownerDID, Key is the CID.
// Returns a GetObjectOutput containing the object data stream and metadata.
// The caller must close the Body when done reading.
func (c *Client) GetObject(
	ctx context.Context,
	input *GetObjectInput,
	opts ...GetObjectOpt,
) (*GetObjectOutput, error) {
	options := getGetObjectOptions(opts...)

	// Get key
	if input.Key == nil || *input.Key == "" {
		return nil, errors.New("filesdk: object name (CID) is required")
	}

	// Get application DID
	if c.appDID == "" {
		return nil, errors.New("filesdk: application DID is not configured")
	}

	// Get gateway trust JWT
	if c.gatewayTrustJWT == "" {
		return nil, errors.New("filesdk: gateway trust JWT is not configured")
	}

	// Get auth client
	if c.authClient == nil {
		return nil, errors.New("filesdk: auth client is not configured")
	}

	// Set viewer Priv key hex if provided
	if c.viewerPrivKeyHex != nil && *c.viewerPrivKeyHex != "" {
		options.providerOpts = append(
			[]crypt.ProviderOpt{crypt.WithPrivKeyHex(*c.viewerPrivKeyHex)},
			options.providerOpts...,
		)
	}

	// Build request & headers
	targetURL := fmt.Sprintf("%s/files/%s", c.endpoint.String(), *input.Key)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to create request: %w", err)
	}

	// Set headers
	headers := make(http.Header)
	if input.Metadata != nil {
		for key, value := range input.Metadata {
			headers.Set(key, value)
		}
	}
	c.mergeHeaders(req.Header, headers)

	// Get authorization from headers
	authorization := strings.TrimSpace(req.Header.Get(headerAuthorization))
	if authorization == "" {
		return nil, errors.New("filesdk: authorization header is required")
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

	// Extract capsule from *original* bearer token to detect Priv objects.
	capsule, capErr := credential.CapsuleFromJWT(normalizedAuthorization)
	if capErr != nil {
		// We treat failure to extract capsule as "no capsule" → public object.
		capsule = ""
	}

	// Default reader: raw response body
	var reader io.ReadCloser = respBody

	// If object is Priv and we have a capsule, decrypt
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

	// Convert metadata to map[string]string
	metadata := make(map[string]string)
	metadata["cid"] = *input.Key
	metadata["size"] = fmt.Sprintf("%d", resp.ContentLength)
	metadata["content-type"] = resp.Header.Get("Content-Type")
	for key, value := range resp.Header {
		metadata[key] = strings.Join(value, ",")
	}

	return &GetObjectOutput{
		Body:     reader,
		Metadata: metadata,
	}, nil
}
